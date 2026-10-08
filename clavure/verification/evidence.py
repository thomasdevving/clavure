"""Evidence records produced by runtime and adversarial verification."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


def now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="milliseconds")


class Observed(StrEnum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Outcome(StrEnum):
    PASS = "PASS"  # noqa: S105 - verdict, not a password
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class ProbeRecord(BaseModel):
    id: str = ""
    timestamp: str = Field(default_factory=now)
    actor: str
    identity_kind: Literal["workload-pod", "synthetic-probe-pod", "controller"]
    executed_in: str
    target: str
    target_host: str
    port: int
    via: Literal["service-dns", "pod-ip", "localhost"]
    command: list[str]
    exec_returncode: int
    raw: dict
    interpretation: Observed
    reason: str
    relevant_policies: list[str] = Field(default_factory=list)

    def finalize(self) -> ProbeRecord:
        digest = hashlib.sha256(
            json.dumps(
                [self.timestamp, self.actor, self.target_host, self.port, self.raw], sort_keys=True
            ).encode()
        ).hexdigest()[:12]
        self.id = f"obs-{digest}"
        return self


def interpret_probe(
    raw: dict, *, target_healthy: bool, enforcement_confirmed: bool
) -> tuple[Observed, str]:
    """Decide what one probe shows. A failed connection alone is never enough."""
    status = raw.get("status")
    if status == "CONNECTED":
        resp = raw.get("response")
        extra = f"; application answered {resp!r}" if resp else ""
        return (
            Observed.ALLOWED,
            f"TCP connection established to {raw.get('resolved')}:{raw.get('port')}{extra}",
        )
    if status == "DNS_ERROR":
        return (
            Observed.INCONCLUSIVE,
            "DNS resolution failed; cannot attribute the failure to NetworkPolicy",
        )
    if status in ("TIMEOUT", "REFUSED", "RESET", "UNREACHABLE"):
        if not target_healthy:
            return (
                Observed.INCONCLUSIVE,
                f"{status}, but the target listener is not confirmed healthy",
            )
        if not enforcement_confirmed:
            return (
                Observed.INCONCLUSIVE,
                f"{status}, but NetworkPolicy enforcement is not confirmed",
            )
        return Observed.BLOCKED, (
            f"{status} while the target listener is healthy and NetworkPolicy enforcement is "
            "confirmed by the canary test"
        )
    return Observed.INCONCLUSIVE, f"probe error: {raw.get('error') or status}"


def outcome_for(expected: Observed, observed: Observed) -> Outcome:
    if observed == Observed.INCONCLUSIVE:
        return Outcome.INCONCLUSIVE
    return Outcome.PASS if observed == expected else Outcome.FAIL
