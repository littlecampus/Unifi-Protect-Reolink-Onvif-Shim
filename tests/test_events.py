"""AI-to-motion translation (opt-in) and passthrough observation."""

from shimlib import events, soap
from tests.support import ai, motion, notification, pull_response


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def translator(hold=10.0, longest=900.0):
    clock = Clock()
    return events.MotionTranslator(
        hold, longest, clock=clock, wall=lambda: "2026-10-11T12:00:09Z"
    ), clock


def motion_values(body: bytes):
    parsed = soap.parse_pull_response(body)
    return [
        (soap.motion_value(n), n.operation)
        for n in parsed.notifications
        if n.topic_path.endswith("CellMotionDetector/Motion")
    ]


def test_observe_counts_without_changing_anything():
    body = pull_response([motion(True), ai("PeopleDetect", True), motion(False)])
    obs = events.observe(body)
    assert (obs.pull_ok, obs.notifications, obs.motion_true, obs.motion_false) == (True, 3, 1, 1)
    assert events.observe(b"<junk").unparsed


def test_initialized_then_on_then_held_off():
    tr, clock = translator(hold=10)
    key = "/onvif/PullSubManager?Idx=00_0"
    first = tr.translate(
        key, pull_response([motion(False, "Initialized"), ai("PeopleDetect", False, "Initialized")])
    )
    assert motion_values(first) == [(False, "Initialized")]
    on = tr.translate(key, pull_response([ai("PeopleDetect", True)]))
    assert motion_values(on) == [(True, "Changed")]
    assert b"MyRuleDetector/PeopleDetect" in on  # original AI message kept
    # Raw pixel motion is dropped in AI mode (it is erratic on Reolink).
    raw = tr.translate(key, pull_response([motion(True)]))
    assert motion_values(raw) == []
    clock.t += 3
    off_pending = tr.translate(key, pull_response([ai("PeopleDetect", False)]))
    assert motion_values(off_pending) == []
    clock.t += 5
    assert motion_values(tr.translate(key, pull_response([]))) == []
    clock.t += 6
    assert motion_values(tr.translate(key, pull_response([]))) == [(False, "Changed")]
    assert motion_values(tr.translate(key, pull_response([]))) == []
    assert tr.stats.synthetic_on == 1 and tr.stats.synthetic_off == 2  # Initialized + held off


def test_dropout_within_hold_does_not_split_event():
    tr, clock = translator(hold=10)
    key = "k"
    tr.translate(key, pull_response([motion(False, "Initialized")]))
    tr.translate(key, pull_response([ai("PeopleDetect", True)]))
    tr.translate(key, pull_response([ai("PeopleDetect", False)]))
    clock.t += 4
    back = tr.translate(key, pull_response([ai("PeopleDetect", True)]))
    assert motion_values(back) == []  # still on, no second "on"
    clock.t += 20
    assert motion_values(tr.translate(key, pull_response([]))) == []
    assert tr.stats.synthetic_off == 1  # only the Initialized false


def test_multiple_ai_detectors_or_together():
    tr, clock = translator(hold=0)
    key = "k"
    tr.translate(key, pull_response([motion(False, "Initialized")]))
    assert motion_values(tr.translate(key, pull_response([ai("PeopleDetect", True)]))) == [
        (True, "Changed")
    ]
    assert motion_values(tr.translate(key, pull_response([ai("VehicleDetect", True)]))) == []
    assert motion_values(tr.translate(key, pull_response([ai("PeopleDetect", False)]))) == []
    out = tr.translate(key, pull_response([ai("VehicleDetect", False)]))
    assert motion_values(out) == [(False, "Changed")]


def test_subscriptions_and_cameras_are_isolated():
    a, _ = translator(hold=0)
    b, _ = translator(hold=0)
    a.translate("s1", pull_response([motion(False, "Initialized")]))
    a.translate("s2", pull_response([motion(False, "Initialized")]))
    b.translate("s1", pull_response([motion(False, "Initialized")]))
    assert motion_values(a.translate("s1", pull_response([ai("PeopleDetect", True)]))) == [
        (True, "Changed")
    ]
    # The other subscription on the same camera and the other camera are unaffected.
    assert motion_values(a.translate("s2", pull_response([]))) == []
    assert motion_values(b.translate("s1", pull_response([]))) == []
    assert a.subscriptions["s1"].reported is True and a.subscriptions["s2"].reported is False


def test_resubscription_initialized_resets_state():
    tr, _ = translator(hold=10)
    tr.translate("k", pull_response([motion(False, "Initialized")]))
    tr.translate("k", pull_response([ai("PeopleDetect", True)]))
    again = tr.translate(
        "k", pull_response([motion(False, "Initialized"), ai("PeopleDetect", False, "Initialized")])
    )
    assert motion_values(again) == [(False, "Initialized")]
    assert tr.subscriptions["k"].off_due is None


def test_shim_restart_with_unknown_state_still_delivers_off():
    # A fresh translator (shim restarted) sees AI "false" mid-subscription: Protect may
    # still believe motion is on, so an off is emitted rather than suppressed.
    tr, clock = translator(hold=0)
    out = tr.translate("k", pull_response([ai("PeopleDetect", False)]))
    assert tr.subscriptions["k"].reported is None or motion_values(out) == [(False, "Changed")]
    out = tr.translate("k", pull_response([ai("PeopleDetect", False)]))
    assert tr.stats.synthetic_off >= 1


def test_stuck_motion_guard_forces_off_and_rearms():
    tr, clock = translator(hold=10, longest=60)
    tr.translate("k", pull_response([motion(False, "Initialized")]))
    tr.translate("k", pull_response([ai("PeopleDetect", True)]))
    clock.t += 61
    forced = tr.translate("k", pull_response([]))
    assert motion_values(forced) == [(False, "Changed")] and tr.stats.forced_off == 1
    # Next genuine detection starts a new event.
    again = tr.translate("k", pull_response([ai("PeopleDetect", True)]))
    assert motion_values(again) == [(True, "Changed")]


def test_template_is_namespace_self_contained():
    tr, _ = translator(hold=0)
    tr.translate("k", pull_response([motion(False, "Initialized")]))
    # The next response declares prefixes differently; the stored template still parses.
    other = pull_response([ai("PeopleDetect", True)]).replace(b"tns1", b"topics")
    out = tr.translate("k", other)
    parsed = soap.parse_pull_response(out)
    synthetic = [
        n for n in parsed.notifications if n.topic_path.endswith("CellMotionDetector/Motion")
    ]
    assert len(synthetic) == 1
    scope = synthetic[0].node.in_scope()
    prefix = synthetic[0].topic.split(":")[0]
    assert scope[prefix] == "http://www.onvif.org/ver10/topics"


def test_ai_template_fallback_when_no_raw_motion_topic():
    tr, _ = translator(hold=0)
    out = tr.translate("k", pull_response([ai("PeopleDetect", True, "Initialized")]))
    assert motion_values(out) == [(True, "Initialized")]
    assert b'Name="IsMotion"' in out


def test_non_ai_and_unparseable_responses_pass_through():
    tr, _ = translator()
    other = pull_response([notification("Device/Trigger/DigitalInput", "LogicalState", "true")])
    assert tr.translate("k", other) is other
    junk = b"<not-closed"
    assert tr.translate("k", junk) is junk and tr.stats.unparsed == 1


def test_subscription_state_is_bounded():
    tr, clock = translator()
    for i in range(40):
        tr.translate(f"s{i}", pull_response([motion(False, "Initialized")]))
    assert len(tr.subscriptions) == events.MAX_SUBSCRIPTIONS
    clock.t += events.SUBSCRIPTION_IDLE_SECONDS + 1
    tr.translate("fresh", pull_response([]))
    assert list(tr.subscriptions) == ["fresh"]
