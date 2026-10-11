"""Namespace-aware SOAP inspection and WS-Addressing repair by byte splicing.

The document is parsed (expat, no DTD, bounded depth/size) only to *locate*
elements; edits are byte-range insertions into the original bytes. Nothing is
re-serialized, so WS-Security tokens, reference parameters, QName prefix
declarations and every unrelated byte are preserved exactly.

Repair is fail-transparent: whenever a safe edit is not possible (signed XML,
ambiguous structure, unsupported encoding, malformed input) the original bytes
are returned unchanged with an outcome explaining why, so the camera sees what
it would have seen without the shim.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from xml.parsers import expat
from xml.sax.saxutils import escape

SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
SOAP_NS = frozenset({SOAP11, SOAP12})
WSA10 = "http://www.w3.org/2005/08/addressing"
WSA04 = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
ANONYMOUS = {WSA10: WSA10 + "/anonymous", WSA04: WSA04 + "/role/anonymous"}
EVENTS = "http://www.onvif.org/ver10/events/wsdl"
WSNT = "http://docs.oasis-open.org/wsn/b-2"
SCHEMA = "http://www.onvif.org/ver10/schema"
DSIG = "http://www.w3.org/2000/09/xmldsig#"
XMLNS = "http://www.w3.org/XML/1998/namespace"

# Operations whose requests Reolink's gSOAP rejects without WS-Addressing.
ACTIONS = {
    (EVENTS, "PullMessages"): EVENTS + "/PullPointSubscription/PullMessagesRequest",
    (EVENTS, "SetSynchronizationPoint"): EVENTS
    + "/PullPointSubscription/SetSynchronizationPointRequest",
    (WSNT, "Renew"): "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest",
    (WSNT, "Unsubscribe"): "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/"
    "UnsubscribeRequest",
}
MUST_UNDERSTAND = frozenset({"To", "Action"})
INSERT_ORDER = ("MessageID", "ReplyTo", "To", "Action")
MAX_DEPTH = 64
MAX_NODES = 20000
TAG_NAME = re.compile(rb"<([^\s/>]+)")


class UnsafeXML(ValueError):
    """Raised for input the shim refuses to parse or edit; .category is loggable."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


@dataclass(eq=False)
class Node:
    name: tuple[str, str]
    start: int
    open_end: int
    parent: Node | None
    raw_name: bytes
    empty: bool
    attrs: dict[str, str]
    ns_decls: dict[str | None, str]
    close_start: int = 0
    end: int = 0
    text_parts: list[str] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "".join(self.text_parts)

    def child(self, ns: str, local: str) -> Node | None:
        for child in self.children:
            if child.name == (ns, local):
                return child
        return None

    def in_scope(self) -> dict[str | None, str]:
        """Prefix -> namespace bindings visible at this element."""
        chain = []
        node = self
        while node is not None:
            chain.append(node.ns_decls)
            node = node.parent
        scope: dict[str | None, str] = {}
        for decls in reversed(chain):
            scope.update(decls)
        return scope


def _check_encoding(data: bytes) -> None:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data:
        raise UnsafeXML("encoding")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise UnsafeXML("encoding") from None


def parse_xml(data: bytes, *, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES):
    """Bounded, DTD-free UTF-8 parse returning (root, nodes) with byte spans."""
    _check_encoding(data)
    parser = expat.ParserCreate(namespace_separator="|")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack: list[Node] = []
    nodes: list[Node] = []
    pending: dict[str | None, str] = {}

    def forbidden(*_):
        raise UnsafeXML("dtd")

    def declaration(version, encoding, standalone):
        if encoding and encoding.lower() not in {"utf-8", "utf8", "us-ascii"}:
            raise UnsafeXML("encoding")

    def namespace(prefix, uri):
        pending[prefix] = uri or ""

    def start(name, attrs):
        if len(stack) >= max_depth or len(nodes) >= max_nodes:
            raise UnsafeXML("limits")
        offset = parser.CurrentByteIndex
        quote = None
        end = offset
        size = len(data)
        while end < size:
            char = data[end]
            if quote:
                if char == quote:
                    quote = None
            elif char in (34, 39):
                quote = char
            elif char == 62:
                break
            end += 1
        match = TAG_NAME.match(data, offset)
        if match is None or end >= size:
            raise UnsafeXML("malformed")
        ns, sep, local = name.rpartition("|")
        node = Node(
            name=(ns if sep else "", local),
            start=offset,
            open_end=end + 1,
            parent=stack[-1] if stack else None,
            raw_name=match.group(1),
            empty=data[end - 1 : end] == b"/",
            attrs=dict(attrs),
            ns_decls=dict(pending),
        )
        pending.clear()
        if stack:
            stack[-1].children.append(node)
        nodes.append(node)
        stack.append(node)

    def finish(name):
        node = stack.pop()
        if node.empty:
            node.close_start = node.end = node.open_end
        else:
            node.close_start = parser.CurrentByteIndex
            node.end = data.index(b">", node.close_start) + 1

    def text(value):
        if stack:
            stack[-1].text_parts.append(value)

    parser.StartElementHandler = start
    parser.EndElementHandler = finish
    parser.CharacterDataHandler = text
    parser.StartNamespaceDeclHandler = namespace
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.UnparsedEntityDeclHandler = forbidden
    parser.NotationDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.XmlDeclHandler = declaration
    try:
        parser.Parse(data, True)
    except UnsafeXML:
        raise
    except (expat.ExpatError, ValueError, IndexError, RecursionError):
        raise UnsafeXML("malformed") from None
    if not nodes:
        raise UnsafeXML("malformed")
    return nodes[0], nodes


def apply_edits(data: bytes, edits: list[tuple[int, int, bytes]]) -> bytes:
    if not edits:
        return data
    chunks = []
    position = 0
    for start, end, replacement in sorted(edits, key=lambda e: (e[0], e[1])):
        if start < position:
            raise UnsafeXML("overlap")
        chunks.append(data[position:start])
        chunks.append(replacement)
        position = end
    chunks.append(data[position:])
    return b"".join(chunks)


@dataclass(frozen=True)
class Envelope:
    root: Node
    nodes: list[Node]
    header: Node | None
    body: Node
    operation: tuple[str, str] | None


def parse_envelope(data: bytes) -> Envelope:
    root, nodes = parse_xml(data)
    if root.name[0] not in SOAP_NS or root.name[1] != "Envelope":
        raise UnsafeXML("not_soap")
    env_ns = root.name[0]
    headers = [n for n in root.children if n.name == (env_ns, "Header")]
    bodies = [n for n in root.children if n.name == (env_ns, "Body")]
    if len(headers) > 1 or len(bodies) != 1:
        raise UnsafeXML("ambiguous")
    if headers and root.children.index(headers[0]) > root.children.index(bodies[0]):
        raise UnsafeXML("ambiguous")
    body = bodies[0]
    operation = body.children[0].name if len(body.children) == 1 else None
    return Envelope(root, nodes, headers[0] if headers else None, body, operation)


@dataclass(frozen=True)
class RepairResult:
    body: bytes
    outcome: str
    operation: str | None = None
    added: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.added)


def _element(local: str, ns: str, env_ns: str, value: str, must_understand: bool) -> bytes:
    mu = f' xmlns:s="{env_ns}" s:mustUnderstand="1"' if must_understand else ""
    if local == "ReplyTo":
        inner = f"<wsa:Address>{escape(value)}</wsa:Address>"
    else:
        inner = escape(value)
    return f'<wsa:{local} xmlns:wsa="{ns}"{mu}>{inner}</wsa:{local}>'.encode()


def repair_request(
    data: bytes,
    *,
    to_url: str,
    wanted: tuple[str, ...] = ("To", "Action"),
    must_understand: bool = True,
    message_id=None,
) -> RepairResult:
    """Add only the missing WS-Addressing headers that `wanted` names."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return RepairResult(data, "skipped_encoding")
    if not data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<"):
        return RepairResult(data, "not_xml")
    try:
        env = parse_envelope(data)
    except UnsafeXML as exc:
        return RepairResult(data, f"skipped_{exc.category}")
    op = env.operation[1] if env.operation else None
    action = ACTIONS.get(env.operation) if env.operation else None
    if action is None:
        return RepairResult(data, "not_applicable", op)
    env_ns = env.root.name[0]
    children = env.header.children if env.header is not None else []
    addressing = [n for n in children if n.name[0] in ANONYMOUS]
    versions = {n.name[0] for n in addressing}
    if len(versions) > 1:
        return RepairResult(data, "skipped_ambiguous", op)
    wsa_ns = next(iter(versions), WSA10)
    missing = []
    for local in INSERT_ORDER:
        present = [n for n in addressing if n.name[1] == local]
        if len(present) > 1:
            return RepairResult(data, "skipped_ambiguous", op)
        if not present and local in wanted:
            missing.append(local)
    if not missing:
        return RepairResult(data, "complete", op)
    if any(n.name == (DSIG, "Signature") for n in env.nodes):
        return RepairResult(data, "skipped_signed", op)
    values = {
        "To": to_url,
        "Action": action,
        "MessageID": f"urn:uuid:{message_id or uuid.uuid4()}",
        "ReplyTo": ANONYMOUS[wsa_ns],
    }
    fragment = b"".join(
        _element(local, wsa_ns, env_ns, values[local], must_understand and local in MUST_UNDERSTAND)
        for local in missing
    )
    header = env.header
    if header is None:
        edit = (
            env.body.start,
            env.body.start,
            f'<s:Header xmlns:s="{env_ns}">'.encode() + fragment + b"</s:Header>",
        )
    elif header.empty:
        opening = data[header.start : header.open_end - 2].rstrip() + b">"
        edit = (header.start, header.end, opening + fragment + b"</" + header.raw_name + b">")
    else:
        edit = (header.open_end, header.open_end, fragment)
    return RepairResult(apply_edits(data, [edit]), "repaired", op, tuple(missing))


# --- Event notifications -------------------------------------------------


@dataclass(eq=False)
class Notification:
    node: Node
    topic: str
    topic_path: str
    message: Node | None
    operation: str | None
    data: list[tuple[str, str]]

    @property
    def first_value(self) -> str | None:
        return self.data[0][1] if self.data else None


@dataclass(eq=False)
class PullResponse:
    root: Node
    nodes: list[Node]
    response: Node | None
    fault: bool
    notifications: list[Notification]


def topic_path(topic: str) -> str:
    """Strip a QName prefix from a topic expression: 'tns1:A/B' -> 'A/B'."""
    head, sep, rest = topic.partition(":")
    if sep and "/" not in head:
        return rest
    return topic


def parse_pull_response(data: bytes) -> PullResponse:
    env = parse_envelope(data)
    env_ns = env.root.name[0]
    fault = env.operation == (env_ns, "Fault")
    response = None
    notifications = []
    if env.operation == (EVENTS, "PullMessagesResponse"):
        response = env.body.children[0]
        for item in response.children:
            if item.name != (WSNT, "NotificationMessage"):
                continue
            topic_node = item.child(WSNT, "Topic")
            topic = topic_node.text.strip() if topic_node is not None else ""
            wrapper = item.child(WSNT, "Message")
            message = wrapper.child(SCHEMA, "Message") if wrapper is not None else None
            data_items = []
            operation = None
            if message is not None:
                operation = message.attrs.get("PropertyOperation")
                data_node = message.child(SCHEMA, "Data")
                if data_node is not None:
                    for simple in data_node.children:
                        if simple.name == (SCHEMA, "SimpleItem"):
                            data_items.append(
                                (simple.attrs.get("Name", ""), simple.attrs.get("Value", ""))
                            )
            notifications.append(
                Notification(item, topic, topic_path(topic), message, operation, data_items)
            )
    return PullResponse(env.root, env.nodes, response, fault, notifications)


MOTION_SUFFIXES = ("CellMotionDetector/Motion", "VideoSource/MotionAlarm")
MOTION_ITEMS = ("IsMotion", "State")


def motion_value(note: Notification) -> bool | None:
    """True/False for a camera motion notification, None for anything else."""
    if not note.topic_path.endswith(MOTION_SUFFIXES):
        return None
    for name, value in note.data:
        if name in MOTION_ITEMS:
            lowered = value.strip().lower()
            if lowered in ("true", "1"):
                return True
            if lowered in ("false", "0"):
                return False
    return None


def self_contained(data: bytes, node: Node) -> bytes:
    """Return node's bytes with every inherited namespace binding declared on it.

    The fragment can then be inserted into another document without changing the
    meaning of any element prefix or QName-valued text (such as a Topic).
    """
    inherited = node.parent.in_scope() if node.parent is not None else {}
    extra = []
    for prefix, uri in sorted(inherited.items(), key=lambda kv: (kv[0] is not None, kv[0] or "")):
        if prefix in node.ns_decls:
            continue
        if prefix is None:
            extra.append(f' xmlns="{escape(uri, {chr(34): "&quot;"})}"')
        else:
            extra.append(f' xmlns:{prefix}="{escape(uri, {chr(34): "&quot;"})}"')
    fragment = data[node.start : node.end]
    if not extra:
        return fragment
    split = 1 + len(node.raw_name)
    return fragment[:split] + "".join(extra).encode() + fragment[split:]
