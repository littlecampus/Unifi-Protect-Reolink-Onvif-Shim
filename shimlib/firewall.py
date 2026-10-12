"""Scoped nat OUTPUT redirects for the NVR-local shim.

Layout (nat table only; nothing else is modified or flushed):

    -A OUTPUT -p tcp -m owner --uid-owner <protect uid> \
        -m comment --comment onvif-shim:jump -j ONVIF_SHIM
    -A ONVIF_SHIM -m conntrack --ctstate INVALID \
        -m comment --comment onvif-shim:ct-anchor -j RETURN
    -A ONVIF_SHIM -d <camera>/32 -p tcp -m tcp --dport <onvif port> \
        -m comment --comment onvif-shim:cam:<id> -j DNAT --to-destination 127.0.0.1:<listen>

Only connections *created by Protect's uid* to a configured camera ONVIF port
are redirected. The shim runs under a different uid, so its own upstream
connections never match (loop prevention without SO_MARK or privileges). nat
OUTPUT only sees locally originated connections, and only their first packet;
replies and later packets follow the conntrack entry.

The anchor rule never matches anything that reaches nat OUTPUT; it exists to
hold a reference on connection tracking. On a UNVR whose nat table is otherwise
empty, conntrack is inactive until a DNAT rule exists, and removing the *last*
DNAT rule deactivates it: verified on a real kernel (tests/kernel), an
already-redirected long poll then hangs because its replies are no longer
un-NAT'd. With the anchor in place, adding/removing camera redirects never
toggles conntrack, so in-flight requests drain cleanly. The anchor is removed
(returning the nat table to its pre-install state) only when the integration is
uninstalled or has no enabled camera.

All changes are one atomic iptables-restore --noflush transaction, verified by
reading the table back.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field

CHAIN = "ONVIF_SHIM"
TAG = "onvif-shim"
JUMP_COMMENT = f"{TAG}:jump"
ANCHOR_COMMENT = f"{TAG}:ct-anchor"
CAM_COMMENT = f"{TAG}:cam:"
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_./:!-]+")
LOCK_WAIT = "10"
ANCHOR = [
    "-m",
    "conntrack",
    "--ctstate",
    "INVALID",
    "-m",
    "comment",
    "--comment",
    ANCHOR_COMMENT,
    "-j",
    "RETURN",
]


class FirewallError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Redirect:
    camera_id: str
    camera_ip: str
    onvif_port: int
    listen_port: int

    def args(self) -> list[str]:
        return [
            "-d",
            f"{self.camera_ip}/32",
            "-p",
            "tcp",
            "-m",
            "tcp",
            "--dport",
            str(self.onvif_port),
            "-m",
            "comment",
            "--comment",
            CAM_COMMENT + self.camera_id,
            "-j",
            "DNAT",
            "--to-destination",
            f"127.0.0.1:{self.listen_port}",
        ]


def jump_args(uid: int) -> list[str]:
    return [
        "-p",
        "tcp",
        "-m",
        "owner",
        "--uid-owner",
        str(uid),
        "-m",
        "comment",
        "--comment",
        JUMP_COMMENT,
        "-j",
        CHAIN,
    ]


def chain_rules(desired: set[Redirect]) -> list[list[str]]:
    return [ANCHOR] + [r.args() for r in sorted(desired)]


class Runner:
    """Executes commands; tests substitute a fake."""

    def run(self, argv: list[str], input: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv, input=input, capture_output=True, text=True, timeout=60, check=False
        )


def _option(tokens: list[str], name: str) -> str | None:
    try:
        return tokens[tokens.index(name) + 1]
    except (ValueError, IndexError):
        return None


@dataclass
class Jump:
    tokens: list[str]
    uid: int | None


@dataclass
class State:
    chain_exists: bool = False
    rules: list[list[str]] = field(default_factory=list)  # our chain, in order
    redirects: set[Redirect] = field(default_factory=set)
    anchor: bool = False
    foreign_in_chain: list[str] = field(default_factory=list)
    jumps: list[Jump] = field(default_factory=list)
    # Non-integration nat OUTPUT DNAT rules for camera ip:port (e.g. legacy single-camera shim).
    foreign_dnat: list[tuple[str, int]] = field(default_factory=list)

    @property
    def installed(self) -> bool:
        return self.chain_exists or bool(self.jumps)


def parse_redirect(tokens: list[str]) -> Redirect | None:
    comment = _option(tokens, "--comment") or ""
    dest = _option(tokens, "-d") or ""
    dport = _option(tokens, "--dport") or ""
    target = _option(tokens, "--to-destination") or ""
    if (
        not comment.startswith(CAM_COMMENT)
        or _option(tokens, "-p") != "tcp"
        or _option(tokens, "-j") != "DNAT"
        or not dest.endswith("/32")
        or not dport.isdigit()
        or not target.startswith("127.0.0.1:")
        or not target.split(":", 1)[1].isdigit()
    ):
        return None
    expected = Redirect(comment[len(CAM_COMMENT) :], dest[:-3], int(dport), int(target[10:]))
    return expected if expected.args() == tokens else None


def parse_state(save_output: str) -> State:
    """Parse `iptables -t nat -S` output."""
    state = State()
    for line in save_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if tokens[:2] == ["-N", CHAIN]:
            state.chain_exists = True
        elif tokens[:2] == ["-A", CHAIN]:
            rest = tokens[2:]
            state.rules.append(rest)
            redirect = parse_redirect(rest)
            if rest == ANCHOR:
                state.anchor = True
            elif redirect is None:
                state.foreign_in_chain.append(line)
            else:
                state.redirects.add(redirect)
        elif tokens[:2] == ["-A", "OUTPUT"]:
            rest = tokens[2:]
            if _option(rest, "-j") == CHAIN:
                uid = _option(rest, "--uid-owner")
                state.jumps.append(Jump(rest, int(uid) if uid and uid.isdigit() else None))
            elif _option(rest, "-j") == "DNAT":
                dest = _option(rest, "-d") or ""
                dport = _option(rest, "--dport") or ""
                if dest.endswith("/32") and dport.isdigit():
                    state.foreign_dnat.append((dest[:-3], int(dport)))
    return state


def _restore_line(prefix: list[str], tokens: list[str]) -> str:
    if not all(SAFE_TOKEN.fullmatch(t) for t in tokens):
        raise FirewallError("refusing to edit a rule with unexpected tokens; fix manually")
    return " ".join(prefix + tokens)


def plan(state: State, desired: set[Redirect], uid: int | None, *, anchor: bool = True):
    """iptables-restore input moving `state` to `desired`; [] when already there.

    anchor=True keeps the chain (with its conntrack anchor) even with no redirect;
    anchor=False with no redirect removes the integration entirely.
    """
    lines: list[str] = []
    if uid is None or (not desired and not anchor):
        for jump in state.jumps:
            lines.append(_restore_line(["-D", "OUTPUT"], jump.tokens))
        if state.chain_exists:
            lines += [f"-F {CHAIN}", f"-X {CHAIN}"]
    else:
        want = jump_args(uid)
        if not state.chain_exists:
            lines.append(f":{CHAIN} - [0:0]")
        expected = chain_rules(desired)
        if not state.chain_exists or state.rules != expected:
            lines.append(f"-F {CHAIN}")
            for rule in expected:
                lines.append(_restore_line(["-A", CHAIN], rule))
        kept = False
        for jump in state.jumps:
            if jump.tokens == want and not kept:
                kept = True
            else:
                lines.append(_restore_line(["-D", "OUTPUT"], jump.tokens))
        if not kept:
            lines.append(_restore_line(["-I", "OUTPUT", "1"], want))
    if not lines:
        return []
    return ["*nat", *lines, "COMMIT"]


class Firewall:
    def __init__(
        self, runner: Runner, iptables: str = "iptables", restore: str = "iptables-restore"
    ):
        self.runner = runner
        self.iptables = iptables
        self.restore = restore

    def read(self) -> State:
        result = self.runner.run([self.iptables, "-w", LOCK_WAIT, "-t", "nat", "-S"])
        if result.returncode != 0:
            raise FirewallError(f"iptables -S failed (rc={result.returncode})")
        return parse_state(result.stdout)

    def converge(
        self,
        desired: set[Redirect],
        uid: int | None,
        *,
        anchor: bool = True,
        dry_run: bool = False,
    ):
        """Apply and verify. Returns (restore_lines, state_after)."""
        state = self.read()
        lines = plan(state, desired, uid, anchor=anchor)
        if not lines or dry_run:
            return lines, state
        result = self.runner.run(
            [self.restore, "-w", LOCK_WAIT, "--noflush"], input="\n".join(lines) + "\n"
        )
        if result.returncode != 0:
            raise FirewallError(f"iptables-restore failed (rc={result.returncode})")
        after = self.read()
        if plan(after, desired, uid, anchor=anchor):
            raise FirewallError("firewall did not converge to the desired redirects")
        return lines, after

    def remove_all(self, *, dry_run: bool = False):
        return self.converge(set(), None, anchor=False, dry_run=dry_run)
