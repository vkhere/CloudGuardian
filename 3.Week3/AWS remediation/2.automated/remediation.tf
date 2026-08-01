# ============================================================
# Auto-Remediation with Email Notification (Terraform)
# ============================================================

# SNS Topic for Notifications
resource "aws_sns_topic" "remediation" {
  name = "${var.project}-remediation"
  tags = { Name = "${var.project}-remediation" }
}

# Email Subscription (Change to your email)
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.remediation.arn
  protocol  = "email"
  endpoint  = "megha22knit@gmail.com" # ← CHANGE THIS
}

# Lambda Role
resource "aws_iam_role" "lambda_role" {
  name = "${var.project}-remediation-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda Function
resource "aws_lambda_function" "remediator" {
  filename      = "remediation-lambda.zip"
  function_name = "${var.project}-remediator"
  role          = aws_iam_role.lambda_role.arn
  handler       = "remediator.lambda_handler"
  runtime       = "python3.12"
  timeout       = 300

  environment {
    variables = {
      DRY_RUN = "false"
    }
  }
}

# EventBridge + SNS Trigger (for future Prowler integration)

resource "aws_iam_policy" "remediation_actions" {
  name        = "cloudguardian-remediation-actions"
  description = "Least-privilege permissions for CloudGuardian auto-remediation Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PublicAccessBlock"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Sid    = "S3Encryption"
        Effect = "Allow"
        Action = [
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration"
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Sid    = "IAMKeyManagement"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = "arn:aws:iam::735291151388:user/*"
      },
      {
        Sid      = "RDSDescribe"
        Effect   = "Allow"
        Action   = ["rds:DescribeDBInstances"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediation_actions" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.remediation_actions.arn
}

