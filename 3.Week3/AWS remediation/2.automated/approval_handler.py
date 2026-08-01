"""
CloudGuardian Approval Workflow - Approval Handler Lambda
Triggered by API Gateway when the person clicks the Approve
or Reject link in the email. Resumes the paused Step Function
by calling SendTaskSuccess (approve) or SendTaskFailure (reject).
"""

import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sfn = boto3.client("stepfunctions")


def html_response(title, message):
    body = f"""<html><body style="font-family: sans-serif; text-align:center; padding-top:60px;">
<h2>{title}</h2><p>{message}</p></body></html>"""
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html"},
        "body": body,
    }


def lambda_handler(event, context):
    params = event.get("queryStringParameters") or {}
    task_token = params.get("token")
    action = params.get("action")
    bucket_name = params.get("bucket", "unknown")
    finding_type = params.get("finding", "unknown")

    if not task_token or action not in ("approve", "reject"):
        logger.error(f"Invalid request: {json.dumps(params)}")
        return html_response("Invalid request", "Missing or malformed parameters.")

    try:
        if action == "approve":
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps({
                    "decision": "approve",
                    "bucket_name": bucket_name,
                    "finding_type": finding_type,
                })
            )
            logger.info(json.dumps({
                "action": "approved",
                "bucket": bucket_name,
                "finding": finding_type
            }))
            return html_response(
                "✅ Approved",
                f"Remediation for '{finding_type}' on '{bucket_name}' is now running."
            )
        else:
            sfn.send_task_failure(
                taskToken=task_token,
                error="RejectedByUser",
                cause=f"Rejected via email for {bucket_name} / {finding_type}"
            )
            logger.info(json.dumps({
                "action": "rejected",
                "bucket": bucket_name,
                "finding": finding_type
            }))
            return html_response(
                "❌ Rejected",
                f"No action was taken for '{finding_type}' on '{bucket_name}'."
            )
    except sfn.exceptions.TaskTimedOut:
        return html_response("Link expired", "This approval request has already timed out.")
    except sfn.exceptions.InvalidToken:
        return html_response("Already responded", "This approval link has already been used or is invalid.")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return html_response("Error", "Something went wrong processing your response.")
