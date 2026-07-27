"""
CloudGuardian Approval Workflow - Notifier Lambda
Invoked BY Step Functions as a "waitForTaskToken" task.
Builds properly URL-encoded Approve/Reject links (the task
token contains characters that break URLs if not encoded)
and publishes the approval email via SNS.

IMPORTANT: this function does NOT call SendTaskSuccess itself.
The Step Function state stays paused until the approval_handler
Lambda (triggered by the link click) calls SendTaskSuccess or
SendTaskFailure with the same task token.
"""

import boto3
import json
import os
import logging
import urllib.parse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
API_ENDPOINT = os.environ["API_ENDPOINT"].rstrip("/")


def build_link(action, task_token, bucket_name, finding_type):
    params = {
        "token": task_token,
        "action": action,
        "bucket": bucket_name,
        "finding": finding_type,
    }
    query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return f"{API_ENDPOINT}/respond?{query}"


def lambda_handler(event, context):
    task_token = event["TaskToken"]
    finding_type = event["finding_type"]
    bucket_name = event["bucket_name"]

    approve_link = build_link("approve", task_token, bucket_name, finding_type)
    reject_link = build_link("reject", task_token, bucket_name, finding_type)

    message = (
        f"CloudGuardian detected a misconfiguration that needs your approval.\n\n"
        f"Finding: {finding_type}\n"
        f"Resource: {bucket_name}\n\n"
        f"This link expires in 1 hour.\n\n"
        f"APPROVE (fix it now):\n{approve_link}\n\n"
        f"REJECT (do nothing):\n{reject_link}\n"
    )

    logger.info(json.dumps({
        "action": "send_approval_email",
        "finding": finding_type,
        "resource": bucket_name
    }))

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"CloudGuardian: Approval needed - {finding_type}",
        Message=message,
    )

    # Do not return a decision here - the workflow stays paused
    # until approval_handler.py calls SendTaskSuccess/Failure.
    return {"statusCode": 200, "body": "Approval email sent"}
