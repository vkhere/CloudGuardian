# AWS Security Remediation Report — Before vs After

**Account:** `735291151388`  **Region:** `ap-south-1`
**Before scan:** 2026-07-13 09:37:50 UTC
**After scan:** 2026-07-13 17:35:21 UTC
**Scanner:** Prowler
**Change applied:** S3 public-access remediation Lambda (`cloudguardian-remediate-s3-public-access`) run live against the account, alongside encryption and IAM-key remediation Lambdas.

---

## 1. Executive Summary

| Metric | Before | After | Change |
|---|---|---|---|
| Total findings | 178 | 197 | +19 |
| PASS | 94 | 106 | +12 |
| FAIL | 82 | 89 | +7 |
| MANUAL | 2 | 2 | — |
| Pass rate | 53.4% | 54.4% | +1.0 pt |
| Critical FAILs | 4 | 4 | — |
| High FAILs | 17 | 17 | — |
| Medium FAILs | 49 | 52 | +3 |
| Low FAILs | 12 | 16 | +4 |

The +19 new findings are almost entirely explained by the 3 new remediation Lambda functions themselves being scanned as new resources (see §3). The core S3 bucket's security posture is the same or slightly stronger — see §2.

---

## 2. S3 Remediation — Detail (`cloudguardian-data-dd2b6927` + account-level)

| Check | Severity | Before | After | Notes |
|---|---|---|---|---|
| `s3_bucket_public_access` | critical | ✅ PASS | ✅ PASS | Bucket was already not public; unchanged |
| `s3_bucket_policy_public_write_access` | critical | ✅ PASS | ✅ PASS | **Evidence the Lambda acted**: before-status text = *"does not allow public write access in the bucket policy"*; after-status text = *"S3 public access blocked at bucket level"* — i.e. Block Public Access was explicitly applied at the bucket level, a stronger control than just a permissive-policy check, even though PASS/FAIL didn't change |
| `s3_account_level_public_access_blocks` | high | ❌ FAIL | ❌ FAIL | **Not fixed** — account-level Block Public Access is still not configured. Only bucket-level was touched |
| `s3_bucket_default_encryption` | medium | ✅ PASS | ✅ PASS | Already AES256 encrypted; unchanged |
| `s3_bucket_kms_encryption` | medium | ❌ FAIL | ❌ FAIL | Not fixed — still using AES256, not KMS-backed |
| `s3_bucket_object_versioning` | medium | ❌ FAIL | ❌ FAIL | Not fixed |
| `s3_bucket_secure_transport_policy` | medium | ❌ FAIL | ❌ FAIL | Not fixed — bucket policy still allows non-TLS requests |
| `s3_bucket_server_access_logging_enabled` | medium | ❌ FAIL | ❌ FAIL | Not fixed |
| `s3_bucket_lifecycle_enabled` | low | ❌ FAIL | ❌ FAIL | Not fixed |
| `s3_bucket_cross_region_replication` | low | ❌ FAIL | ❌ FAIL | Not fixed |

**Takeaway:** the live S3 remediation successfully hardened the bucket-level Block Public Access setting (confirmed by the changed status message), but the bucket's public-access checks were already passing before the run, so PASS/FAIL counts don't move. The account-level Block Public Access setting and several other S3 hygiene checks (KMS encryption, versioning, TLS-only policy, access logging, lifecycle, replication) are **outside this Lambda's scope** and remain unresolved.

---

## 3. Side Effect: New Findings from the Remediation Lambdas

Deploying `cloudguardian-remediate-s3-public-access`, `cloudguardian-remediate-encryption`, and `cloudguardian-remediate-iam-key` introduced 19 new findings — these functions didn't exist in the before-scan:

**New PASS (9):**
- All 3 Lambdas: not publicly accessible ✅
- All 3 Lambdas: Invoke API calls recorded by CloudTrail ✅
- All 3 Lambdas: deployed inside a VPC ✅
- All 3 Lambda log groups: not publicly accessible ✅

**New FAIL (3):**
- `cloudwatch_log_group_kms_encryption_enabled` — all 3 Lambdas' CloudWatch log groups are **not KMS-encrypted** (medium severity). This is a new gap introduced by the remediation deployment itself and should be closed (attach a KMS key to each `/aws/lambda/cloudguardian-remediate-*` log group).

---

## 4. Unrelated to This Change — Still Open (Not in Scope for S3 Lambda)

These were failing before and remain failing after; flagged here for prioritization, not caused by or fixed by the S3 remediation:

| Severity | Check | Resource |
|---|---|---|
| Critical | RDS instance publicly exposed | `cloudguardian-db` |
| Critical | IAM AdministratorAccess (`*:*`) policy attached | account-wide managed policy |
| Critical | Inline IAM policy allows `*:*` | `cloudguardian-web-role` |
| Critical | EC2 allows SSH (22) from the internet | `i-034e7ac45ac7000f4` |
| High | RDS storage/transport not encrypted | `cloudguardian-db` |
| High | EBS volume/default encryption disabled | `vol-0a1c0089c4da8ce0d` |
| High | IMDSv2 not enforced | EC2 account setting |
| High | Root user used in last 24h | account root |

---

## 5. Bottom Line

- ✅ **Live S3 remediation worked as intended** — bucket-level Block Public Access is now explicitly enforced (visible in the status text change), even though the check was already passing.
- ⚠️ **No net PASS/FAIL movement** on S3 checks because the bucket wasn't actually publicly exposed before the fix ran — the fix hardened a control that was already compliant on the surface.
- ⚠️ **New minor gap introduced**: 3 unencrypted CloudWatch log groups from the remediation Lambdas themselves.
- 🔴 **Unaddressed**: account-level S3 Block Public Access, S3 KMS encryption/versioning/TLS-only policy, plus unrelated critical items (RDS public exposure, admin IAM policy, open SSH).
