# AWS identity detection lab

Lab-only Python project aligned with interview prep for **cloud and identity detections** (AWS CloudTrail-shaped events, benign baselines vs suspicious patterns). Not production telemetry and not a live AWS account requirement.

## What this is

- Synthetic JSON events in `fixtures/synthetic_events.json` (identity-focused: IAM, STS AssumeRole, console root MFA context).
- Detection functions in `src/detections.py` with explicit **baseline allowlists** so you can talk about false positives and environment context (Damien’s framing: behavior, noise, knowledge of good).
- `pytest` proves which events fire which rules.

## Run tests

```bash
cd aws-identity-detection-lab
pip install -r requirements.txt
python -m pytest tests/ -q
```

## Interview prompts this supports

- Which AWS log sources matter for identity: CloudTrail (management events), `signin.amazonaws.com` for console, STS for role assumption, IAM for keys and users.
- How you separate **automation on baseline IPs** from **CreateAccessKey** or **AssumeRole** from a new IP.
- How you would enrich with org context (IP allowlists, role sensitivity, break-glass accounts) in a real program.

## Next steps (optional)

- Add GuardDuty finding shape or VPC Flow sidecar examples as separate fixtures.
- Add Azure AD / Entra ID parallel module under `src/` with the same pytest pattern (identity is the theme, multi-cloud is the story).

See **VERIFICATION.md** for the evidence table.
