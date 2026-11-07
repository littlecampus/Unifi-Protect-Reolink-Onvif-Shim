import re

import pytest

from shimlib import soap
from tests.support import WSSE, create_body, pull_body, renew_body

TO = "http://10.48.20.13:8000/onvif/PullSubManager?Idx=00_0&x=1"
WSA = soap.WSA10


def repair(body, **kw):
    kw.setdefault("to_url", TO)
    return soap.repair_request(body, **kw)


def header_children(body):
    env = soap.parse_envelope(body)
    return [n.name for n in env.header.children] if env.header else []


def test_protect_shaped_pull_gets_to_and_action_and_keeps_wssecurity_bytes():
    body = pull_body()
    result = repair(body)
    assert result.outcome == "repaired" and result.added == ("To", "Action")
    assert WSSE.encode() in result.body  # WS-Security token bytes untouched
    names = header_children(result.body)
    assert (WSA, "To") in names and (WSA, "Action") in names
    env = soap.parse_envelope(result.body)
    to = next(n for n in env.header.children if n.name == (WSA, "To"))
    assert to.text == TO  # query string preserved, & escaped in XML and decoded back
    assert b"Idx=00_0&amp;x=1" in result.body
    # Original bytes survive as an exact subsequence: only an insertion happened.
    inserted = len(result.body) - len(body)
    pos = result.body.index(b"<wsa:To")
    assert result.body[:pos] + result.body[pos + inserted :] == body


def test_missing_to_only_vs_missing_action_only():
    action = soap.ACTIONS[(soap.EVENTS, "PullMessages")]
    with_action = pull_body(header=f'<a:Action xmlns:a="{WSA}">{action}</a:Action>' + WSSE)
    result = repair(with_action)
    assert result.added == ("To",)
    with_to = pull_body(header=f'<a:To xmlns:a="{WSA}">{TO.replace("&", "&amp;")}</a:To>')
    result = repair(with_to)
    assert result.added == ("Action",)
    assert result.body.count(b"To xmlns") == 1  # existing To preserved, not duplicated


def test_namespace_declared_but_elements_missing_is_still_repaired():
    # The upstream shortcut ("namespace present => complete") would skip this.
    body = pull_body(
        header=f'<a:ReplyTo xmlns:a="{WSA}"><a:Address>{WSA}/anonymous</a:Address></a:ReplyTo>'
    ).replace(b"<s:Envelope", f'<s:Envelope xmlns:wsa="{WSA}"'.encode())
    assert WSA.encode() in body
    result = repair(body)
    assert result.outcome == "repaired" and result.added == ("To", "Action")


def test_complete_request_is_untouched():
    action = soap.ACTIONS[(soap.EVENTS, "PullMessages")]
    body = pull_body(
        header=f'<a:To xmlns:a="{WSA}">http://other/x</a:To><a:Action xmlns:a="{WSA}">{action}'
        "</a:Action>"
    )
    result = repair(body)
    assert result.outcome == "complete" and result.body is body


def test_existing_valid_addressing_and_reference_parameters_preserved():
    ref = (
        '<sub:SubscriptionId xmlns:sub="urn:x" a:IsReferenceParameter="true">'
        "abc&amp;1</sub:SubscriptionId>"
    )
    body = pull_body(
        header=f'<a:MessageID xmlns:a="{WSA}">urn:uuid:1</a:MessageID>'
        + ref.replace("a:IsRef", f'xmlns:a="{WSA}" a:IsRef')
    )
    result = repair(body, wanted=("To", "Action", "MessageID"))
    assert result.added == ("To", "Action")  # MessageID already there
    assert b"abc&amp;1</sub:SubscriptionId>" in result.body
    assert result.body.count(b"MessageID") == 2  # open+close of the one existing element


def test_optional_message_id_and_reply_to_when_configured():
    result = repair(pull_body(), wanted=("To", "Action", "MessageID", "ReplyTo"), message_id="x")
    assert result.added == ("MessageID", "ReplyTo", "To", "Action")
    assert b"urn:uuid:x" in result.body and b"/anonymous</wsa:Address>" in result.body


def test_must_understand_optional():
    with_mu = repair(pull_body()).body
    without = repair(pull_body(), must_understand=False).body
    assert b'mustUnderstand="1">http' in with_mu and b"mustUnderstand" not in without.replace(
        WSSE.encode(), b""
    )


@pytest.mark.parametrize(
    "factory, op",
    [(renew_body, "Renew")],
)
def test_renew_unsubscribe_setsync_repaired(factory, op):
    result = repair(factory())
    assert result.outcome == "repaired" and result.operation == op
    for name, local in [("Unsubscribe", "Unsubscribe")]:
        body = (
            factory()
            .replace(b"Renew", name.encode())
            .replace(b"<wsnt:TerminationTime>PT60S</wsnt:TerminationTime>", b"")
        )
        assert repair(body).operation == local
    sync = pull_body().replace(b"PullMessages", b"SetSynchronizationPoint")
    sync = re.sub(rb"<tev:Timeout>.*</tev:MessageLimit>", b"", sync)
    assert repair(sync).outcome == "repaired"
    assert soap.ACTIONS[(soap.EVENTS, "SetSynchronizationPoint")].encode() in repair(sync).body


def test_other_operations_are_not_touched():
    body = create_body()
    result = repair(body)
    assert result.outcome == "not_applicable" and result.body is body
    assert result.operation == "CreatePullPointSubscription"


def test_qname_prefixes_preserved_and_local_namespace_used():
    # A document that binds the "wsa" prefix to something else must not be reinterpreted.
    body = pull_body().replace(b"<s:Envelope ", b'<s:Envelope xmlns:wsa="urn:not-addressing" ')
    result = repair(body)
    env = soap.parse_envelope(result.body)
    names = [n.name for n in env.header.children]
    assert (WSA, "To") in names
    assert env.root.ns_decls["wsa"] == "urn:not-addressing"


def test_soap11_and_wsa2004_namespace():
    body = pull_body().replace(soap.SOAP12.encode(), soap.SOAP11.encode())
    result = repair(body)
    assert result.outcome == "repaired" and f'xmlns:s="{soap.SOAP11}"'.encode() in result.body
    old = pull_body(header=f'<b:MessageID xmlns:b="{soap.WSA04}">urn:uuid:9</b:MessageID>')
    result = repair(old)
    assert f'xmlns:wsa="{soap.WSA04}"'.encode() in result.body


def test_no_header_and_empty_header():
    result = repair(pull_body(header=None))
    assert result.outcome == "repaired" and header_children(result.body)[0] == (WSA, "To")
    empty = pull_body(header="").replace(b"<s:Header></s:Header>", b"<s:Header />")
    result = repair(empty)
    assert result.outcome == "repaired" and b"</s:Header>" in result.body


@pytest.mark.parametrize(
    "body, outcome",
    [
        (b"not xml at all", "not_xml"),
        (b"<s:Envelope", "skipped_malformed"),
        (
            b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]>'
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>',
            "skipped_dtd",
        ),
        (b'<?xml version="1.0" encoding="ISO-8859-1"?><a/>', "skipped_encoding"),
        ("<a>é</a>".encode("latin-1"), "skipped_encoding"),
        ("<a/>".encode("utf-16"), "skipped_encoding"),
        (b"<a/>", "skipped_not_soap"),
        (b"<a>" * 100 + b"</a>" * 100, "skipped_limits"),
    ],
)
def test_unsafe_inputs_are_passed_through_unchanged(body, outcome):
    result = repair(body)
    assert result.outcome == outcome and result.body is body


def test_signed_xml_not_modified():
    sig = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature>'
    body = pull_body(header=WSSE.replace("</wsse:Security>", sig + "</wsse:Security>"))
    result = repair(body)
    assert result.outcome == "skipped_signed" and result.body is body


@pytest.mark.parametrize(
    "header",
    [
        f'<a:To xmlns:a="{WSA}">x</a:To><a:To xmlns:a="{WSA}">y</a:To>',
        f'<a:Action xmlns:a="{WSA}">x</a:Action>'
        f'<b:MessageID xmlns:b="{soap.WSA04}">m</b:MessageID>',
    ],
)
def test_duplicate_or_mixed_addressing_is_ambiguous(header):
    result = repair(pull_body(header=header))
    assert result.outcome == "skipped_ambiguous"


def test_header_after_body_is_ambiguous():
    body = (
        f'<s:Envelope xmlns:s="{soap.SOAP12}"><s:Body><tev:PullMessages '
        'xmlns:tev="http://www.onvif.org/ver10/events/wsdl"/></s:Body><s:Header/></s:Envelope>'
    ).encode()
    assert repair(body).outcome == "skipped_ambiguous"


def test_billion_laughs_never_expands():
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY l0 "ha">'
        + b"".join(
            b'<!ENTITY l%d "&l%d;&l%d;&l%d;&l%d;">' % (i, i - 1, i - 1, i - 1, i - 1)
            for i in range(1, 20)
        )
        + b"]><a>&l19;</a>"
    )
    assert repair(bomb).outcome == "skipped_dtd"


def test_self_contained_fragment_carries_inherited_namespaces():
    data = (
        b'<r xmlns="urn:default" xmlns:p="urn:p" xmlns:tns1="urn:topics">'
        b"<p:item><p:t>tns1:A/B</p:t></p:item></r>"
    )
    _, nodes = soap.parse_xml(data)
    fragment = soap.self_contained(data, nodes[1])
    root, frag_nodes = soap.parse_xml(fragment)
    assert root.name == ("urn:p", "item")
    assert root.ns_decls["tns1"] == "urn:topics" and root.ns_decls[None] == "urn:default"
