"""
CloudGuardian Auto-Remediation: Unified Dispatcher
====================================================
Single Lambda entry point triggered via SNS. Reads the finding_type from
the incoming message and routes to the correct remediation handler:

  - M02-S3-PUBLIC-ACCESS-BLOCK  -> remediate_s3_public_access.lambda_handler
  - M01-IAM-EXPOSED-KEY         -> remediate_iam_key_rotation.lambda_handler
  - M07-M09-DEFAULT-ENCRYPTION  -> remediate_default_encryption.lambda_handler
    (RDS branch inside this one is always human-approval, never auto-fixed)

Supports two invocation paths:
  1. Direct test invoke: pass the finding payload directly as `event`,
     with a top-level "finding_type" key.
  2. SNS trigger (production path): event["Records"][0]["Sns"]["Message"]
     contains a JSON string with the same payload shape.

Message input example (either invoked directly or as the SNS Message body):
{
    "finding_type": "M02-S3-PUBLIC-ACCESS-BLOCK",
    "bucket_name": "cloudguardian-target-bucket",
    "dry_run": true,
    "requested_by": "prowler-automation"
}
"""

import json
import logging

import remediate_s3_public_access
import remediate_iam_key_rotation
import remediate_default_encryption

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Maps a finding_type string to the module-level lambda_handler that knows
# how to remediate it. Keeping this as an explicit allow-list (rather than
# dynamic dispatch) so an unrecognized finding_type can never accidentally
# execute unintended code.
FINDING_ROUTES = {
    "M02-S3-PUBLIC-ACCESS-BLOCK": remediate_s3_public_access.lambda_handler,
    "M01-IAM-EXPOSED-KEY": remediate_iam_key_rotation.lambda_handler,
    "M07-M09-DEFAULT-ENCRYPTION": remediate_default_encryption.lambda_handler,
}


def _extract_payload(event):
    """
    Normalizes input from either a direct test invoke or a real SNS trigger
    into a single dict.
    """
    if isinstance(event, dict) and "Records" in event:
        # Real SNS-triggered invocation
        try:
            sns_message = event["Records"][0]["Sns"]["Message"]
            return json.loads(sns_message)
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise ValueError(f"Malformed SNS event - could not extract message: {e}")
    elif isinstance(event, dict):
        # Direct test invocation - event IS the payload
        return event
    else:
        raise ValueError("Event must be a dict (direct payload or SNS envelope)")


def lambda_handler(event, context):
    logger.info(f"Dispatcher received event: {json.dumps(event)[:500]}")

    try:
        payload = _extract_payload(event)
    except ValueError as e:
        logger.error(f"Failed to parse event: {e}")
        return {"statusCode": 400, "body": str(e)}

    finding_type = payload.get("finding_type")
    if not finding_type:
        logger.error("Missing 'finding_type' in payload")
        return {"statusCode": 400, "body": "Missing 'finding_type' in payload"}

    handler = FINDING_ROUTES.get(finding_type)
    if handler is None:
        logger.error(f"Unknown finding_type: {finding_type}")
        return {
            "statusCode": 400,
            "body": f"Unknown finding_type '{finding_type}'. "
                    f"Known types: {list(FINDING_ROUTES.keys())}"
        }

    logger.info(f"Routing finding_type '{finding_type}' to {handler.__module__}")
    return handler(payload, context)

