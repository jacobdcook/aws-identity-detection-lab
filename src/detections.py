"""
Lab-only detection logic over synthetic CloudTrail-shaped JSON.
Interview framing: behavioral identity abuse, benign baselines, environment context.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from models import CloudTrailLikeEvent

# Lab baseline: "known" corporate egress IPs for benign automation (simulated allowlist)
BASELINE_CORPORATE_IPS = frozenset({"203.0.113.10", "203.0.113.11", "198.51.100.50"})

# Simulated high-privilege role ARNs we care about for AssumeRole monitoring
SENSITIVE_ROLE_ARNS = frozenset(
    {
        "arn:aws:iam::111122223333:role/OrgAdmin",
        "arn:aws:iam::111122223333:role/SecurityAudit",
    }
)


def detect_access_key_created_outside_baseline(
    events: Iterable[CloudTrailLikeEvent],
) -> list[tuple[str, str]]:
    """Flag CreateAccessKey when source IP is not in the lab corporate baseline."""
    hits: list[tuple[str, str]] = []
    for e in events:
        if e.event_name != "CreateAccessKey":
            continue
        if e.source_ip in BASELINE_CORPORATE_IPS:
            continue
        hits.append(
            (
                e.event_id,
                "CreateAccessKey from an IP outside the simulated corporate baseline",
            )
        )
    return hits


def detect_assume_role_sensitive_from_new_ip(
    events: Iterable[CloudTrailLikeEvent],
) -> list[tuple[str, str]]:
    """Flag AssumeRole into a sensitive role when IP is not baseline (simulated lateral movement)."""
    hits: list[tuple[str, str]] = []
    for e in events:
        if e.event_name != "AssumeRole":
            continue
        role_arn = str(e.request_params.get("roleArn", ""))
        if role_arn not in SENSITIVE_ROLE_ARNS:
            continue
        if e.source_ip in BASELINE_CORPORATE_IPS:
            continue
        hits.append(
            (
                e.event_id,
                f"AssumeRole into sensitive role from non-baseline IP: {role_arn}",
            )
        )
    return hits


def detect_root_console_without_mfa_context(
    events: Iterable[CloudTrailLikeEvent],
) -> list[tuple[str, str]]:
    """
    Flag ConsoleLogin for root where MFA is not present on the session (lab heuristic).
    Real environments combine with CloudTrail + IAM credential report + org policy.
    """
    hits: list[tuple[str, str]] = []
    for e in events:
        if e.event_name != "ConsoleLogin":
            continue
        ui_type = str(e.user_identity.get("type", ""))
        if ui_type != "Root":
            continue
        sc = e.user_identity.get("sessionContext") or {}
        attrs = sc.get("attributes") or {}
        mfa = attrs.get("mfaAuthenticated")
        if mfa == "true":
            continue
        hits.append((e.event_id, "Root ConsoleLogin without MFA in simulated session context"))
    return hits


def detect_password_spray(
    events: Iterable[CloudTrailLikeEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[tuple[str, str]]:
    """
    Flag source IPs with >= threshold failed ConsoleLogin events within a time window (T1110.003).
    Returns (source_ip, message) tuples — spray is an IP-level finding, not a single event.
    Only considers events that carry an eventTime field.
    """
    failures = [
        e for e in events
        if e.event_name == "ConsoleLogin"
        and e.error_code == "Failed authentication"
        and e.event_time
    ]

    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for f in failures:
        try:
            t = datetime.fromisoformat(f.event_time.replace("Z", "+00:00"))
            by_ip[f.source_ip].append(t)
        except ValueError:
            pass

    hits: list[tuple[str, str]] = []
    window = timedelta(minutes=window_minutes)
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            count = sum(1 for t in times if times[i] <= t < times[i] + window)
            if count >= threshold:
                hits.append(
                    (ip, f"Password spray: {count} failed logins in {window_minutes}m window (T1110.003)")
                )
                break
    return hits


def detect_external_user_created(
    events: Iterable[CloudTrailLikeEvent],
) -> list[tuple[str, str]]:
    """
    Flag CreateUser where the new username looks like an external or guest identity.
    Usernames containing '@' suggest email-format federation or SCIM-imported external accounts.
    """
    hits: list[tuple[str, str]] = []
    for e in events:
        if e.event_name != "CreateUser":
            continue
        username = str(e.request_params.get("userName", ""))
        if "@" in username:
            hits.append((e.event_id, f"External-pattern user created: {username}"))
    return hits
