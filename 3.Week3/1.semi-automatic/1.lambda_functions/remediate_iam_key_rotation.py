"""
CloudGuardian Auto-Remediation: IAM Exposed Access Key
Finding: M01 - IAM wildcard permissions / exposed access key
Severity: CRITICAL

Safe because: We DEACTIVATE (not delete) the key. Deactivation is instantly
REVERSIBLE by an admin re-activating it via IAM console/CLI, unlike deletion
which is permanent and would require regenerating credentials everywhere the
key is used. Deactivating an already-exposed key is a defensive action that
stops further unauthorized use without destroying anything.

Event input example:
{
    "iam_user_name": "Alex",
    "access_key_id": "AKIA...",
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

iam = boto3.client("iam")


def validate_event(event):
    iam_user_name = event.get("iam_user_name")
    access_key_id = event.get("access_key_id")

    if not iam_user_name or not isinstance(iam_user_name, str):
        raise ValueError("Missing or invalid 'iam_user_name' in event input")
    if not access_key_id or not access_key_id.startswith("AKIA"):
        raise ValueError("Missing or invalid 'access_key_id' (must start with AKIA)")

    dry_run = event.get("dry_run", True)
    if not isinstance(dry_run, bool):
        raise ValueError("'dry_run' must be a boolean")

    requested_by = event.get("requested_by", "unknown")
    return iam_user_name, access_key_id, dry_run, requested_by


def log_action(action, iam_user_name, access_key_id, requested_by, dry_run,
               result="SUCCESS", detail=""):
    # NOTE: never log the secret access key, only the key ID (public identifier)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "finding": "M01-IAM-EXPOSED-KEY",
        "iam_user": iam_user_name,
        "access_key_id": access_key_id,
        "requested_by": requested_by,
        "dry_run": dry_run,
        "result": result,
        "detail": detail,
    }
    logger.info(json.dumps(entry))
    return entry


def lambda_handler(event, context):
    try:
        iam_user_name, access_key_id, dry_run, requested_by = validate_event(event)
    except ValueError as e:
        logger.error(f"Input validation failed: {e}")
        return {"statusCode": 400, "body": str(e)}

    # Confirm the key actually belongs to this user and check current status
    try:
        keys = iam.list_access_keys(UserName=iam_user_name)["AccessKeyMetadata"]
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchEntity":
            log_action("check_state", iam_user_name, access_key_id, requested_by,
                       dry_run, "ERROR", "IAM user not found")
            return {"statusCode": 404, "body": f"IAM user '{iam_user_name}' not found"}
        if error_code == "AccessDenied":
            log_action("check_state", iam_user_name, access_key_id, requested_by,
                       dry_run, "ERROR", "Permission denied listing access keys")
            return {"statusCode": 403, "body": "Access denied - Lambda role needs iam:ListAccessKeys"}
        log_action("check_state", iam_user_name, access_key_id, requested_by,
                   dry_run, "ERROR", str(e))
        return {"statusCode": 500, "body": str(e)}

    matching_key = next((k for k in keys if k["AccessKeyId"] == access_key_id), None)
    if matching_key is None:
        log_action("check_state", iam_user_name, access_key_id, requested_by,
                   dry_run, "ERROR", "Key not found for this user")
        return {"statusCode": 404, "body": "Access key not found for given IAM user"}

    if matching_key["Status"] == "Inactive":
        log_action("no_op", iam_user_name, access_key_id, requested_by,
                   dry_run, "SKIPPED", "Key already inactive")
        return {"statusCode": 200, "body": "Key already deactivated - no action needed"}

    if dry_run:
        log_action("dry_run_remediate", iam_user_name, access_key_id, requested_by,
                   dry_run, "SIMULATED", "Would set key status to Inactive")
        return {
            "statusCode": 200,
            "body": f"[DRY RUN] Would deactivate key '{access_key_id}' for user '{iam_user_name}'"
        }

    # Actual remediation: deactivate, not delete
    try:
        iam.update_access_key(
            UserName=iam_user_name,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
        log_action("remediate", iam_user_name, access_key_id, requested_by,
                   dry_run, "SUCCESS", "Key deactivated")
        return {
            "statusCode": 200,
            "body": f"Access key '{access_key_id}' deactivated for user '{iam_user_name}'. "
                    f"Admin can reactivate via IAM console if needed."
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            log_action("remediate", iam_user_name, access_key_id, requested_by,
                       dry_run, "ERROR", "Permission denied updating access key")
            return {"statusCode": 403, "body": "Access denied - Lambda role needs iam:UpdateAccessKey"}
        log_action("remediate", iam_user_name, access_key_id, requested_by,
                   dry_run, "ERROR", str(e))
        return {"statusCode": 500, "body": str(e)}
