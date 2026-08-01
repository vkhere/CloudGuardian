"""
CloudGuardian Auto-Remediation: S3 Public Access Block
Finding: M02/M06 - S3 bucket public-access-block disabled
Severity: HIGH
Safe because: Re-enabling public-access-block is NON-DESTRUCTIVE and REVERSIBLE.
It only blocks NEW public ACLs/policies from taking effect at the account/bucket
level; it does not delete any data, objects, or existing bucket configuration.
If a legitimate business need for public access exists, this can be reverted
in seconds by an admin without any data loss.

Event input example:
{
    "bucket_name": "cloudguardian-target-bucket",
    "dry_run": true,
    "requested_by": "prowler-automation"
}
"""

import boto3
import logging
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3", region_name="ap-south-1")

def validate_event(event):
    """Basic input validation before touching any AWS resource."""
    bucket_name = event.get("bucket_name")
    if not bucket_name or not isinstance(bucket_name, str):
        raise ValueError("Missing or invalid 'bucket_name' in event input")

    dry_run = event.get("dry_run", True)  # default to dry_run=True for safety
    if not isinstance(dry_run, bool):
        raise ValueError("'dry_run' must be a boolean")

    requested_by = event.get("requested_by", "unknown")
    return bucket_name, dry_run, requested_by


def log_action(action, bucket_name, requested_by, dry_run, result="SUCCESS", detail=""):
    """Structured CloudWatch log entry: who/what/when."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "finding": "M02-S3-PUBLIC-ACCESS-BLOCK",
        "resource": bucket_name,
        "requested_by": requested_by,
        "dry_run": dry_run,
        "result": result,
        "detail": detail,
    }
    logger.info(json.dumps(entry))
    return entry


def lambda_handler(event, context):
    try:
        bucket_name, dry_run, requested_by = validate_event(event)
    except ValueError as e:
        logger.error(f"Input validation failed: {e}")
        return {"statusCode": 400, "body": str(e)}

    desired_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    # Check current state first (read-only, always safe to do)
    try:
        current = s3.get_public_access_block(Bucket=bucket_name)
        current_config = current["PublicAccessBlockConfiguration"]
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            current_config = {}  # none set = fully open
        elif error_code == "NoSuchBucket":
            log_action("check_state", bucket_name, requested_by, dry_run,
                       "ERROR", "Bucket not found")
            return {"statusCode": 404, "body": f"Bucket '{bucket_name}' not found"}
        elif error_code == "AccessDenied":
            log_action("check_state", bucket_name, requested_by, dry_run,
                       "ERROR", "Permission denied reading bucket state")
            return {"statusCode": 403, "body": "Access denied - check Lambda execution role permissions"}
    if current_config == desired_config:
        log_action("no_op", bucket_name, requested_by, dry_run,
                   "SKIPPED", "Public access block already fully enabled")
        return {"statusCode": 200, "body": "Already remediated - no action needed"}

    if dry_run:
        log_action("dry_run_remediate", bucket_name, requested_by, dry_run,
                   "SIMULATED", f"Would apply: {desired_config}")
        return {
            "statusCode": 200,
            "body": f"[DRY RUN] Would enable full public access block on '{bucket_name}'"
        }

    # Actual remediation
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=desired_config,
        )
        log_action("remediate", bucket_name, requested_by, dry_run,
                   "SUCCESS", f"Applied: {desired_config}")
        return {"statusCode": 200, "body": f"Public access block enabled on '{bucket_name}'"}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            log_action("remediate", bucket_name, requested_by, dry_run,
                       "ERROR", "Permission denied applying public access block")
            return {"statusCode": 403, "body": "Access denied - Lambda role needs s3:PutBucketPublicAccessBlock"}
        log_action("remediate", bucket_name, requested_by, dry_run, "ERROR", str(e))
        return {"statusCode": 500, "body": str(e)}
