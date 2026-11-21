from pathlib import Path

import load
from detections import (
    BASELINE_CORPORATE_IPS,
    detect_access_key_created_outside_baseline,
    detect_assume_role_sensitive_from_new_ip,
    detect_external_user_created,
    detect_password_spray,
    detect_root_console_without_mfa_context,
    detect_secrets_harvesting,
)

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_events.json"


def _events():
    return load.load_json_events(_FIXTURES)


def test_baseline_ip_count():
    assert len(BASELINE_CORPORATE_IPS) == 3


def test_create_access_key_alerts_on_non_baseline_ip():
    hits = detect_access_key_created_outside_baseline(_events())
    ids = [h[0] for h in hits]
    assert "evt-002" in ids
    assert "evt-003" not in ids


def test_assume_role_sensitive_alerts_on_non_baseline_ip():
    hits = detect_assume_role_sensitive_from_new_ip(_events())
    ids = [h[0] for h in hits]
    assert "evt-004" in ids
    assert "evt-005" not in ids


def test_root_console_without_mfa():
    hits = detect_root_console_without_mfa_context(_events())
    ids = [h[0] for h in hits]
    assert "evt-006" in ids
    assert "evt-007" not in ids


def test_password_spray_detected():
    hits = detect_password_spray(_events())
    ips = [h[0] for h in hits]
    assert "45.33.32.156" in ips


def test_password_spray_single_failure_not_flagged():
    hits = detect_password_spray(_events())
    ips = [h[0] for h in hits]
    assert "203.0.113.99" not in ips


def test_password_spray_threshold_respected():
    hits = detect_password_spray(_events(), threshold=5)
    ips = [h[0] for h in hits]
    assert "45.33.32.156" not in ips


def test_external_user_created_flagged():
    hits = detect_external_user_created(_events())
    ids = [h[0] for h in hits]
    assert "evt-013" in ids


def test_internal_user_not_flagged():
    hits = detect_external_user_created(_events())
    ids = [h[0] for h in hits]
    assert "evt-014" not in ids


_ATTACKER = "arn:aws:sts::111122223333:assumed-role/CiBuildRunner/i-0synthetic01"


def test_secrets_harvesting_flags_attacker_with_denied_recon():
    hits = dict(detect_secrets_harvesting(_events()))
    assert _ATTACKER in hits
    assert "4 secret reads" in hits[_ATTACKER]
    assert "3 AccessDenied" in hits[_ATTACKER]


def test_secrets_harvesting_ignores_baseline_app_role():
    principals = [h[0] for h in detect_secrets_harvesting(_events())]
    assert "arn:aws:sts::111122223333:assumed-role/PaymentsApp/task-01" not in principals


def test_secrets_harvesting_ignores_plaintext_parameter_reads():
    principals = [h[0] for h in detect_secrets_harvesting(_events())]
    assert "arn:aws:sts::111122223333:assumed-role/DevReadOnly/session" not in principals


def test_secrets_harvesting_threshold_respected():
    assert detect_secrets_harvesting(_events(), threshold=5) == []
