"""Read-only view of the third-party cameras Protect knows about.

Reads Protect's own Postgres database (internal, undocumented schema) inside a
READ ONLY transaction that is rolled back. Only identity and status columns are
selected: never the stored camera username/password or stream URLs. If the
schema changes or the database is unreachable, callers get ProtectUnavailable
and can still work from an explicit camera IP.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

DB_NAME = "unifi-protect"
DB_PORT = "5433"
# MAC prefixes observed on the TLC recorder; anything else is reported as Protect's type.
VENDOR_OUI = {"EC71DB": "Reolink", "BC325F": "Dahua"}
QUERY = """\
BEGIN READ ONLY;
SELECT coalesce(json_agg(json_build_object(
    'name', name,
    'host', host,
    'mac', mac,
    'type', type,
    'adopted', "isAdopted",
    'onvif_port', "thirdPartyCameraInfo"->>'port',
    'motion', "thirdPartyCameraInfo"->>'motionDetection'
) ORDER BY "isAdopted" DESC, name NULLS LAST, host), '[]'::json)
FROM cameras WHERE "isThirdPartyCamera";
ROLLBACK;
"""


class ProtectUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ProtectCamera:
    name: str | None
    host: str | None
    mac: str | None
    type: str | None
    adopted: bool
    onvif_port: int | None
    motion: str | None

    @property
    def vendor(self) -> str:
        oui = (self.mac or "").replace(":", "").upper()[:6]
        return VENDOR_OUI.get(oui) or (self.type or "unknown")

    @property
    def is_reolink(self) -> bool:
        return self.vendor == "Reolink"

    @property
    def label(self) -> str:
        return self.name or self.host or self.mac or "?"


def _port(value) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def parse(output: str) -> list[ProtectCamera]:
    try:
        rows = json.loads(output.strip() or "[]")
    except ValueError:
        raise ProtectUnavailable("unexpected output from the Protect database") from None
    if not isinstance(rows, list):
        raise ProtectUnavailable("unexpected output from the Protect database")
    cameras = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cameras.append(
            ProtectCamera(
                name=row.get("name") or None,
                host=row.get("host") or None,
                mac=(row.get("mac") or "").upper() or None,
                type=row.get("type") or None,
                adopted=row.get("adopted") is True,
                onvif_port=_port(row.get("onvif_port")),
                motion=row.get("motion") or None,
            )
        )
    return cameras


def query(runner, *, port: str = DB_PORT, database: str = DB_NAME) -> list[ProtectCamera]:
    """Third-party cameras from Protect (root only: connects as the postgres user)."""
    argv = [
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-p",
        port,
        "-d",
        database,
        "-XAtq",
        "-v",
        "ON_ERROR_STOP=1",
    ]
    try:
        result = runner.run(argv, input=QUERY)
    except OSError as exc:
        raise ProtectUnavailable(f"cannot run psql ({type(exc).__name__})") from None
    if result.returncode != 0:
        raise ProtectUnavailable(
            "Protect database query failed (not on the console, not root, or schema changed)"
        )
    return parse(result.stdout)
