# ============================================================
# s3.tf - Object Storage
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates S3 bucket - MISCONFIGURED STATE
#
# MISCONFIGURATIONS INTRODUCED:
#   [M04] S3 public access block disabled (all 4 flags = false)
#   [M05] S3 versioning suspended
#   [M10] S3 server-side encryption removed entirely
# ============================================================

# Random suffix for globally unique bucket name
resource "random_id" "suffix" {
  byte_length = 4
}

# Main S3 Bucket
resource "aws_s3_bucket" "data" {
  bucket        = "${var.project}-data-${random_id.suffix.hex}"
  force_destroy = true
  tags          = { Name = "${var.project}-bucket" }
}

# ---------------------------------------------------------------
# [M05] MISCONFIGURATION - Versioning suspended
#  Baseline:  status = "Enabled"    (SECURE)
#  Misconfig: status = "Suspended"  (INSECURE)
#
#  Risk: No protection against accidental/malicious file deletion
#        Ransomware can overwrite all objects with no recovery
#  Fix: Change back to "Enabled"
# ---------------------------------------------------------------
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Suspended"    # INSECURE: versioning disabled, no recovery possible
  }
}

# ---------------------------------------------------------------
# [M10] MISCONFIGURATION - S3 server-side encryption REMOVED
#  Baseline:  aws_s3_bucket_server_side_encryption_configuration
#             resource existed with AES256 SSE enabled
#  Misconfig: Entire encryption resource block is DELETED
#
#  Risk: New objects stored without default encryption
#        Compliance violation: GDPR, HIPAA, PCI-DSS all require
#        encryption at rest
#  Fix: Re-add the SSE configuration resource below:
#
#  resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
#    bucket = aws_s3_bucket.data.id
#    rule {
#      apply_server_side_encryption_by_default {
#        sse_algorithm = "AES256"
#      }
#    }
#  }
# ---------------------------------------------------------------
# NOTE: SSE resource intentionally absent - this IS the misconfiguration


# ---------------------------------------------------------------
# [M04] MISCONFIGURATION - Public access block disabled
#  Baseline:  All 4 flags = true   (SECURE - fully blocked)
#  Misconfig: All 4 flags = false  (INSECURE - public access possible)
#
#  Risk: Bucket can be made publicly accessible via bucket policy
#        or ACLs - any data uploaded can be exposed to internet
#  Real-world: Majority of S3 data breach incidents (Capital One,
#              Twitch, etc.) involved disabled public access blocks
#  Fix: Set all 4 flags back to true
# ---------------------------------------------------------------
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false   # INSECURE: public ACLs allowed
  block_public_policy     = false   # INSECURE: public bucket policies allowed
  ignore_public_acls      = false   # INSECURE: public ACLs not ignored
  restrict_public_buckets = false   # INSECURE: bucket can be made public
}
