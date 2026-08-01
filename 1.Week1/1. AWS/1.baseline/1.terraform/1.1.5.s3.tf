# ============================================================
# s3.tf - Object Storage
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates S3 bucket with encryption and versioning
#           Baseline: secure - public access blocked
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

# Enable versioning - protects against accidental deletion
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable default encryption - data at rest is encrypted
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access - baseline secure configuration
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
