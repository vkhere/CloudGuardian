# CloudGuardian Week 3 — Auto-Remediation Lambda Functions

Three safe, reversible auto-remediation functions for findings M01, M02, M07/M09.
All default to `dry_run: true` — nothing executes unless you explicitly pass `"dry_run": false`.

## Files
| File | Finding | Fixes |
|---|---|---|
| `remediate_s3_public_access.py` | M02/M06 | Re-enables S3 Block Public Access |
| `remediate_iam_key_rotation.py` | M01 | Deactivates (not deletes) exposed IAM access key |
| `remediate_default_encryption.py` | M07/M09 | Enables SSE-S3 on buckets; **flags** unencrypted RDS for human approval (does not auto-fix RDS encryption — that requires a disruptive snapshot/restore) |

## Deploy (per function, example for S3 one)
```bash
cd /home/claude/remediation
zip s3_remediation.zip remediate_s3_public_access.py

aws lambda create-function \
  --function-name cloudguardian-remediate-s3-public-access \
  --runtime python3.12 \
  --role arn:aws:iam::735291151388:role/cloudguardian-remediation-role \
  --handler remediate_s3_public_access.lambda_handler \
  --zip-file fileb://s3_remediation.zip \
  --region ap-south-1
```

## IAM role needs (minimum, per function)
- S3 function: `s3:GetPublicAccessBlock`, `s3:PutPublicAccessBlock`
- IAM function: `iam:ListAccessKeys`, `iam:UpdateAccessKey`
- Encryption function: `s3:GetEncryptionConfiguration`, `s3:PutEncryptionConfiguration`, `rds:DescribeDBInstances`

## Test invoke (dry run — safe, default)
```bash
aws lambda invoke \
  --function-name cloudguardian-remediate-s3-public-access \
  --payload '{"bucket_name":"YOUR_BUCKET","dry_run":true,"requested_by":"megha-test"}' \
  --cli-binary-format raw-in-base64-out \
  response.json && cat response.json
```

## Test invoke (real remediation — only after dry run looks correct)
```bash
aws lambda invoke \
  --function-name cloudguardian-remediate-s3-public-access \
  --payload '{"bucket_name":"YOUR_BUCKET","dry_run":false,"requested_by":"megha-manual-approval"}' \
  --cli-binary-format raw-in-base64-out \
  response.json && cat response.json
```

## Note
Replace the M-ID comments (`M01`, `M02`, `M07/M09`) in each file's docstring
with your team's actual catalogue IDs from `05_CSE_Capstone_CloudGuardian.pdf`
if they differ — I used the pattern from your prior CloudGuardian work
(M01=IAM wildcard, M02/M06=S3 public access, M07/M09=encryption).
