# ============================================================
# iam.tf - Identity and Access Management
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates IAM role for EC2 web tier
#
# MISCONFIGURATIONS INTRODUCED:
#   [M01] Wildcard Action ("*") in inline IAM policy
#   [M02] Wildcard Resource ("*") in inline IAM policy
#   [M03] AdministratorAccess managed policy attached to role
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

# ---------------------------------------------------------------
# [M01] + [M02] MISCONFIGURATION - Wildcard Action AND Resource
#
# [M01] Baseline Action: ["s3:GetObject", "s3:ListBucket"]
#       Misconfig Action: ["*"]
#       Risk: EC2 can perform ANY AWS API action (EC2, IAM, RDS...)
#
# [M02] Baseline Resource: [specific_bucket_arn, bucket_arn/*]
#       Misconfig Resource: ["*"]
#       Risk: Policy applies to ALL resources in ALL AWS services
#
# Combined Risk: EC2 instance has FULL unrestricted AWS access
#   - Can create/delete IAM users
#   - Can read all S3 buckets in account
#   - Can terminate any EC2 instance
#   - If EC2 is compromised → entire AWS account is compromised
#
# Fix: Restore specific actions and specific resource ARNs
# ---------------------------------------------------------------
resource "aws_iam_role_policy" "web_policy" {
  name = "${var.project}-s3-read-only"
  role = aws_iam_role.web_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]    # [M01] INSECURE: was ["s3:GetObject", "s3:ListBucket"]
      Resource = ["*"]    # [M02] INSECURE: was [specific_bucket_arn, arn/*]
    }]
  })
}

# ---------------------------------------------------------------
# [M03] MISCONFIGURATION - AdministratorAccess attached to EC2 role
#  Baseline:  No managed policies attached (SECURE)
#  Misconfig: AdministratorAccess policy attached (INSECURE)
#
#  Risk: On top of M01+M02 wildcard inline policy, this ALSO
#        grants full AWS admin via AWS managed policy
#        Dual path to complete account compromise
#
#  Real-world: If web server is hacked (e.g., RCE via Apache),
#              attacker can run `aws iam create-user --user-name backdoor`
#              and establish persistent access to entire account
#
#  Fix: Delete this resource entirely
# ---------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.web_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # INSECURE: full admin
}

# IAM Instance Profile - attaches role to EC2
resource "aws_iam_instance_profile" "web_profile" {
  name = "${var.project}-web-profile"
  role = aws_iam_role.web_role.name
}
