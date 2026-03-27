# AWS log sources (identity and abuse) — cheat sheet

Use this in interviews. Wording is generic; tune to the org.

| Source | Why it matters |
|--------|----------------|
| **CloudTrail (management events)** | IAM, STS, KMS control plane. Backbone for “who changed trust, who created keys, who assumed roles.” |
| **CloudTrail (data events)** | S3 / DynamoDB object-level when enabled. Often off by default; know the gap. |
| **AWS Console sign-in events** | `ConsoleLogin`, MFA context, root vs IAM user. |
| **VPC Flow Logs** | Not identity by itself; use with CloudTrail for “odd IP path to STS.” |
| **GuardDuty** | Correlated findings; triage layer on top of raw CloudTrail. |

**Follow-up answer:** “I start with CloudTrail for identity changes, align to a CMDB or IP allowlist for automation, then tune so scheduled jobs and break-glass do not page the team.”
