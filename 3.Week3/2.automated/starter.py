"""
CloudGuardian Approval Workflow - Starter Lambda
Subscribed to the SNS topic that used to trigger remediation
directly. Now it starts a Step Function execution instead,
which pauses for human approval before remediating.
"""

import boto3
import json
import os
import logging
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sfn = boto3.client("stepfunctions")
STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]


def lambda_handler(event, context):
    for record in event.get("Records", []):
        sns_message = record["Sns"]["Message"]
        finding = json.loads(sns_message)

        execution_name = f"finding-{uuid.uuid4().hex[:8]}"
	finding["dry_run"] = False

        logger.info(json.dumps({
            "action": "start_approval_workflow",
            "execution_name": execution_name,
            "finding": finding
        }))

        sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=execution_name,
            input=json.dumps(finding)
        )

    return {"statusCode": 200, "body": "Approval workflow(s) started"}
