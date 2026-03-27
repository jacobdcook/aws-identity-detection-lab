# Verification

| Check | Command | Expected |
|-------|---------|----------|
| Rules on synthetic CloudTrail-like JSON | `python -m pytest tests/ -q` | All tests pass |

All metrics and matches are against **fixtures/synthetic_events.json** only.
