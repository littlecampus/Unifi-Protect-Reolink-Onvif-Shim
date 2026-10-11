"""PullMessages response observation (passthrough) and optional AI-to-motion translation.

Passthrough mode never changes response bytes; it only counts what the camera
sent so health can say "a real camera motion notification reached Protect's
socket" (which still is not proof Protect recorded an event).

ai_motion mode is opt-in per camera. State is keyed per subscription (the
PullMessages request target) so cameras and subscriptions never share state.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from . import soap

AI_TOPIC = re.compile(r"MyRuleDetector/\w*Detect$")
SYNTH_TOPIC = "RuleEngine/CellMotionDetector/Motion"
MAX_SUBSCRIPTIONS = 16
SUBSCRIPTION_IDLE_SECONDS = 1800.0
ATTR = r"""(\s{name}\s*=\s*)(["'])(.*?)\2"""


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Observation:
    pull_ok: bool = False
    fault: bool = False
    notifications: int = 0
    motion_true: int = 0
    motion_false: int = 0
    unparsed: bool = False


def observe(payload: bytes) -> Observation:
    """Classify a PullMessages response body without modifying it."""
    result = Observation()
    try:
        parsed = soap.parse_pull_response(payload)
    except soap.UnsafeXML:
        result.unparsed = True
        return result
    result.fault = parsed.fault
    result.pull_ok = parsed.response is not None
    result.notifications = len(parsed.notifications)
    for note in parsed.notifications:
        value = soap.motion_value(note)
        if value is True:
            result.motion_true += 1
        elif value is False:
            result.motion_false += 1
    return result


@dataclass
class Template:
    """A self-contained NotificationMessage plus byte spans of the fields we replace."""

    data: bytes
    from_ai: bool

    def render(self, value: bool, operation: str, when: str) -> bytes | None:
        out = self.data
        out, n_op = _replace_attr(out, "PropertyOperation", operation)
        out, n_time = _replace_attr(out, "UtcTime", when)
        if self.from_ai:
            out, n_topic = _replace_topic(out)
            out, n_name = _replace_item_name(out)
            if not (n_topic and n_name):
                return None
        out, n_value = _replace_data_value(out, "true" if value else "false")
        if not (n_op and n_time and n_value):
            return None
        return out


def _replace_attr(data: bytes, name: str, value: str) -> tuple[bytes, int]:
    # Only within the tt:Message start tag: find the first tag carrying the attribute.
    pattern = re.compile(ATTR.format(name=name).encode(), re.S)
    return pattern.subn(lambda m: m.group(1) + m.group(2) + value.encode() + m.group(2), data, 1)


def _replace_topic(data: bytes) -> tuple[bytes, int]:
    pattern = re.compile(rb"(<(?:[\w.-]+:)?Topic\b[^>]*>)\s*([\w.-]+:)?[^<]*(</)", re.S)
    return pattern.subn(
        lambda m: m.group(1) + (m.group(2) or b"") + SYNTH_TOPIC.encode() + m.group(3), data, 1
    )


def _data_section(data: bytes) -> tuple[int, int] | None:
    match = re.search(rb"<(?:[\w.-]+:)?Data\b[^>]*>(.*?)</(?:[\w.-]+:)?Data>", data, re.S)
    return match.span(1) if match else None


def _replace_in_data(data: bytes, pattern: re.Pattern, repl) -> tuple[bytes, int]:
    span = _data_section(data)
    if span is None:
        return data, 0
    inner, count = pattern.subn(repl, data[span[0] : span[1]], 1)
    return data[: span[0]] + inner + data[span[1] :], count


def _replace_item_name(data: bytes) -> tuple[bytes, int]:
    pattern = re.compile(ATTR.format(name="Name").encode(), re.S)
    return _replace_in_data(
        data, pattern, lambda m: m.group(1) + m.group(2) + b"IsMotion" + m.group(2)
    )


def _replace_data_value(data: bytes, value: str) -> tuple[bytes, int]:
    pattern = re.compile(ATTR.format(name="Value").encode(), re.S)
    return _replace_in_data(
        data, pattern, lambda m: m.group(1) + m.group(2) + value.encode() + m.group(2)
    )


@dataclass
class SubscriptionState:
    active: set[str] = field(default_factory=set)
    reported: bool | None = None  # what Protect was last told; None = unknown
    off_due: float | None = None
    on_since: float | None = None
    template: Template | None = None
    last_seen: float = 0.0


@dataclass
class TranslateStats:
    synthetic_on: int = 0
    synthetic_off: int = 0
    forced_off: int = 0
    raw_dropped: int = 0
    no_template: int = 0
    unparsed: int = 0


class MotionTranslator:
    """Drive Protect motion from Reolink AI detections, per subscription."""

    def __init__(self, off_hold: float, max_motion: float, clock=time.monotonic, wall=utc_now):
        self.off_hold = off_hold
        self.max_motion = max_motion
        self.clock = clock
        self.wall = wall
        self.subscriptions: OrderedDict[str, SubscriptionState] = OrderedDict()
        self.stats = TranslateStats()
        self.transitions: list[str] = []  # drained by the caller for logging

    def _state(self, key: str, now: float) -> SubscriptionState:
        for stale in [
            k
            for k, s in self.subscriptions.items()
            if now - s.last_seen > SUBSCRIPTION_IDLE_SECONDS
        ]:
            del self.subscriptions[stale]
        state = self.subscriptions.pop(key, None) or SubscriptionState()
        state.last_seen = now
        self.subscriptions[key] = state
        while len(self.subscriptions) > MAX_SUBSCRIPTIONS:
            self.subscriptions.popitem(last=False)
        return state

    def translate(self, key: str, payload: bytes) -> bytes:
        """Return the (possibly) rewritten PullMessagesResponse body."""
        now = self.clock()
        try:
            parsed = soap.parse_pull_response(payload)
        except soap.UnsafeXML:
            self.stats.unparsed += 1
            return payload
        if parsed.response is None or parsed.response.empty:
            return payload
        state = self._state(key, now)
        edits: list[tuple[int, int, bytes]] = []
        initialized = False
        ai_changed = False
        raw_template = None
        for note in parsed.notifications:
            if note.operation == "Initialized":
                initialized = True
            if soap.motion_value(note) is not None or note.topic_path.endswith(
                soap.MOTION_SUFFIXES
            ):
                if raw_template is None and note.message is not None:
                    raw_template = Template(soap.self_contained(payload, note.node), False)
                edits.append((note.node.start, note.node.end, b""))
                continue
            if AI_TOPIC.search(note.topic_path) and note.first_value is not None:
                on = note.first_value.strip().lower() in ("true", "1")
                (state.active.add if on else state.active.discard)(note.topic_path)
                ai_changed = True
                if state.template is None or state.template.from_ai:
                    state.template = Template(soap.self_contained(payload, note.node), True)
        if raw_template is not None:
            state.template = raw_template
        if initialized:
            # A (re)subscription: the camera's Initialized values are the truth.
            state.off_due = None
            state.reported = None
        if state.template is None:
            if edits:
                self.stats.no_template += 1
            return payload  # nothing safe to synthesize; leave the camera's bytes alone
        self.stats.raw_dropped += len(edits)
        when = self.wall()
        synthetic: list[bytes] = []

        def emit(value: bool, operation: str, reason: str) -> bool:
            rendered = state.template.render(value, operation, when)
            if rendered is None:
                self.stats.no_template += 1
                return False
            synthetic.append(rendered)
            state.reported = value
            state.on_since = now if value else None
            if value:
                self.stats.synthetic_on += 1
            else:
                self.stats.synthetic_off += 1
            self.transitions.append(f"motion_{'on' if value else 'off'}:{reason}")
            return True

        desired = bool(state.active)
        if initialized:
            emit(desired, "Initialized", "initialized")
        elif desired:
            state.off_due = None
            if state.reported is not True:
                emit(True, "Changed", "ai")
        elif ai_changed and state.reported is not False and state.off_due is None:
            state.off_due = now + self.off_hold
        if state.off_due is not None and now >= state.off_due and not state.active:
            state.off_due = None
            emit(False, "Changed", "ai_clear")
        if (
            state.reported is True
            and self.max_motion > 0
            and state.on_since is not None
            and now - state.on_since >= self.max_motion
        ):
            # Lost "false" (outage/reboot) must not pin motion on forever.
            state.active.clear()
            state.off_due = None
            if emit(False, "Changed", "stuck_guard"):
                self.stats.forced_off += 1
        if not edits and not synthetic:
            return payload
        if synthetic:
            close = parsed.response.close_start
            edits.append((close, close, b"".join(synthetic)))
        try:
            return soap.apply_edits(payload, edits)
        except soap.UnsafeXML:
            self.stats.unparsed += 1
            return payload

    def snapshot(self) -> dict:
        return {
            "subscriptions": len(self.subscriptions),
            "motion_reported": [s.reported for s in self.subscriptions.values()],
            **self.stats.__dict__,
        }
