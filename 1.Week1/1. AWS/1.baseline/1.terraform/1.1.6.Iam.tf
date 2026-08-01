# ============================================================
# iam.tf - Identity and Access Management
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates IAM role for EC2 web tier with
#           least privilege S3 read-only access
#           Baseline: minimal permissions only
# ============================================================

# IAM Role - allows EC2 to assume this role
resource "aws_iam_role" "web_role" {
  name = "${var.project}-web-role"

  # Trust policy - only EC2 can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project}-web-role" }
}

# IAM Policy - least privilege S3 read only
# Baseline secure: NO wildcard actions, NO admin access
resource "aws_iam_role_policy" "web_policy" {
  name = "${var.project}-s3-read-only"
  role = aws_iam_role.web_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",   # Read objects only
        "s3:ListBucket"   # List bucket contents only
      ]
      Resource = [
        aws_s3_bucket.data.arn,
        "${aws_s3_bucket.data.arn}/*"
      ]
    }]
  })
}

# IAM Instance Profile - attaches role to EC2
resource "aws_iam_instance_profile" "web_profile" {
  name = "${var.project}-web-profile"
  role = aws_iam_role.web_role.name
}
