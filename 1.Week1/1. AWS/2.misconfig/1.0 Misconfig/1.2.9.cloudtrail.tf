resource "aws_cloudtrail" "main" {
  name                          = "cloudguardian-trail"
  s3_bucket_name                = aws_s3_bucket.data.id
  enable_log_file_validation    = false
  is_multi_region_trail         = false
  include_global_service_events = false

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ---------------------------------------------------------------
# S3 Bucket Policy - required so CloudTrail can write logs
#  Without this, AWS rejects trail creation with:
#  "InsufficientS3BucketPolicyException"
# ---------------------------------------------------------------
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.data.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.data.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
