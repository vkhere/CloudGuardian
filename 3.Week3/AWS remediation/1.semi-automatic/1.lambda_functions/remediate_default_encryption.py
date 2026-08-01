"""
CloudGuardian Auto-Remediation: Default Encryption (S3 / RDS)
Finding: M07/M09 - S3 bucket / RDS instance without default encryption
Severity: HIGH

Safe because: Enabling default (SSE-S3/SSE-KMS) encryption is NON-DESTRUCTIVE.
For S3, it only affects how NEW objects are encrypted going forward - existing
objects and bucket contents are untouched. For RDS, this function only flags
unencrypted instances for reporting (RDS encryption cannot be toggled on an
existing instance without a snapshot-restore, which IS potentially disruptive
and destroys the original instance identity - so that case is explicitly
routed to "requires human approval" rather than auto-remediated).

Event input example:
{
    "resource_type": "s3",           # "s3" or "rds"
    "resource_id": "cloudguardian-target-bucket",
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
rds = boto3.client("rds", region_name="ap-south-1")


def validate_event(event):
    resource_type = event.get("resource_type")
    resource_id = event.get("resource_id")

    if resource_type not in ("s3", "rds"):
        raise ValueError("'resource_type' must be 's3' or 'rds'")
    if not resource_id or not isinstance(resource_id, str):
        raise ValueError("Missing or invalid 'resource_id' in event input")

    dry_run = event.get("dry_run", True)
    if not isinstance(dry_run, bool):
        raise ValueError("'dry_run' must be a boolean")

    requested_by = event.get("requested_by", "unknown")
    return resource_type, resource_id, dry_run, requested_by


def log_action(action, resource_type, resource_id, requested_by, dry_run,
               result="SUCCESS", detail=""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "finding": "M07-M09-DEFAULT-ENCRYPTION",
        "resource_type": resource_type,
        "resource_id": resource_id,
        "requested_by": requested_by,
        "dry_run": dry_run,
        "result": result,
        "detail": detail,
    }
    logger.info(json.dumps(entry))
    return entry


def remediate_s3(resource_id, dry_run, requested_by):
    try:
        current = s3.get_bucket_encryption(Bucket=resource_id)
        rules = current["ServerSideEncryptionConfiguration"]["Rules"]
        if rules:
            log_action("no_op", "s3", resource_id, requested_by, dry_run,
                       "SKIPPED", "Default encryption already enabled")
            return {"statusCode": 200, "body": "Already encrypted - no action needed"}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            pass  # expected - means it's NOT encrypted yet, proceed to remediate
        elif error_code == "NoSuchBucket":
            log_action("check_state", "s3", resource_id, requested_by, dry_run,
                       "ERROR", "Bucket not found")
            return {"statusCode": 404, "body": f"Bucket '{resource_id}' not found"}
        elif error_code == "AccessDenied":
            log_action("check_state", "s3", resource_id, requested_by, dry_run,
                       "ERROR", "Permission denied reading encryption state")
            return {"statusCode": 403, "body": "Access denied - Lambda role needs s3:GetEncryptionConfiguration"}
        else:
            log_action("check_state", "s3", resource_id, requested_by, dry_run,
                       "ERROR", str(e))
            return {"statusCode": 500, "body": str(e)}

    if dry_run:
        log_action("dry_run_remediate", "s3", resource_id, requested_by, dry_run,
                   "SIMULATED", "Would enable SSE-S3 default encryption")
        return {"statusCode": 200, "body": f"[DRY RUN] Would enable default encryption on '{resource_id}'"}

    try:
        s3.put_bucket_encryption(
            Bucket=resource_id,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        log_action("remediate", "s3", resource_id, requested_by, dry_run,
                   "SUCCESS", "SSE-S3 (AES256) default encryption enabled")
        return {"statusCode": 200, "body": f"Default encryption (AES256) enabled on '{resource_id}'"}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            log_action("remediate", "s3", resource_id, requested_by, dry_run,
                       "ERROR", "Permission denied applying encryption")
            return {"statusCode": 403, "body": "Access denied - Lambda role needs s3:PutEncryptionConfiguration"}
        log_action("remediate", "s3", resource_id, requested_by, dry_run, "ERROR", str(e))
        return {"statusCode": 500, "body": str(e)}


def remediate_rds(resource_id, dry_run, requested_by):
    """
    RDS storage encryption CANNOT be enabled on a live instance - it requires
    snapshot -> encrypted-copy -> restore, which creates a NEW instance and
    is disruptive (new endpoint, brief downtime). This is NOT auto-remediated;
    we only detect and flag it for human approval.
    """
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=resource_id)
        instance = response["DBInstances"][0]
        is_encrypted = instance.get("StorageEncrypted", False)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "DBInstanceNotFound":
            log_action("check_state", "rds", resource_id, requested_by, dry_run,
                       "ERROR", "RDS instance not found")
            return {"statusCode": 404, "body": f"RDS instance '{resource_id}' not found"}
        if error_code == "AccessDenied":
            log_action("check_state", "rds", resource_id, requested_by, dry_run,
                       "ERROR", "Permission denied describing RDS instance")
            return {"statusCode": 403, "body": "Access denied - Lambda role needs rds:DescribeDBInstances"}
        log_action("check_state", "rds", resource_id, requested_by, dry_run,
                   "ERROR", str(e))
        return {"statusCode": 500, "body": str(e)}

    if is_encrypted:
        log_action("no_op", "rds", resource_id, requested_by, dry_run,
                   "SKIPPED", "RDS instance already encrypted")
        return {"statusCode": 200, "body": "Already encrypted - no action needed"}

    # Always flagged, never auto-fixed - this is intentional, not a dry_run branch
    log_action("flag_for_approval", "rds", resource_id, requested_by, dry_run,
               "REQUIRES_HUMAN_APPROVAL",
               "RDS encryption requires snapshot+restore (disruptive) - not safe to auto-remediate")
    return {
        "statusCode": 200,
        "body": f"RDS instance '{resource_id}' is unencrypted. This requires a "
                f"snapshot-restore cycle which causes downtime - routed to human "
                f"approval queue, NOT auto-remediated."
    }


def lambda_handler(event, context):
    try:
        resource_type, resource_id, dry_run, requested_by = validate_event(event)
    except ValueError as e:
        logger.error(f"Input validation failed: {e}")
        return {"statusCode": 400, "body": str(e)}

    if resource_type == "s3":
        return remediate_s3(resource_id, dry_run, requested_by)
    else:
        return remediate_rds(resource_id, dry_run, requested_by)
