terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

# ---------------------------------------------------------------------------
# Shared execution role for all 3 CloudGuardian remediation Lambda functions
# ---------------------------------------------------------------------------
resource "aws_iam_role" "remediation_lambda_role" {
  name = "cloudguardian-remediation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })

  tags = {
    Project = "CloudGuardian"
    Purpose = "Week3-AutoRemediation"
  }
}

# Basic Lambda execution (CloudWatch Logs) - required for all 3 functions
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.remediation_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------------------------------------------------------------------------
# Least-privilege inline policy: only the exact actions the 3 functions need
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "remediation_permissions" {
  name = "cloudguardian-remediation-permissions"
  role = aws_iam_role.remediation_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PublicAccessRemediation"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration"
        ]
        Resource = "*"
      },
      {
        Sid    = "IamKeyRemediation"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "RdsEncryptionCheck"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

output "role_arn" {
  value = aws_iam_role.remediation_lambda_role.arn
}

output "role_name" {
  value = aws_iam_role.remediation_lambda_role.name
}
