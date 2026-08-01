#!/bin/bash
# ============================================================
# collect_all_evidence.sh
# Project : CloudGuardian - CAP-CSE-3W (Week 2)
# Purpose : Run Steampipe queries for ALL misconfigurations
#           (M01-M12 + CloudTrail) in one shot and export
#           each result to its own CSV file for evidence.
#
# Usage   : chmod +x collect_all_evidence.sh
#           ./collect_all_evidence.sh
#
# Requires: steampipe service running, AWS credentials valid
#           for the `kali` user (not root).
# ============================================================

set -e

# ---- Config ----
OUTDIR="./steampipe_evidence_$(date +%d%b%Y)"
mkdir -p "$OUTDIR"

echo "=============================================="
echo " Verifying Steampipe + AWS connectivity..."
echo "=============================================="
steampipe query "select account_id, account_aliases from aws_account" --output csv

echo ""
echo "Evidence will be saved to: $OUTDIR"
echo "=============================================="

run_query () {
  local name="$1"
  local sql="$2"
  echo "-> Running: $name"
  steampipe query "$sql" --output csv > "$OUTDIR/${name}.csv"
}

# ------------------------------------------------------------
# IAM - M01, M02, M03
# ------------------------------------------------------------
run_query "M01_M02_iam_role_inline_policy_wildcards" "
select
  name as role_name,
  inline_policies_std -> 'PolicyDocument' -> 'Statement' as statements
from
  aws_iam_role
where
  name = 'cloudguardian-web-role';
"

run_query "M03_iam_role_attached_managed_policies" "
select
  r.name as role_name,
  p.policy_arn
from
  aws_iam_role r,
  jsonb_array_elements_text(r.attached_policy_arns) as p(policy_arn)
where
  r.name = 'cloudguardian-web-role';
"

# ------------------------------------------------------------
# S3 - M04, M05, M10
# ------------------------------------------------------------
run_query "M04_s3_public_access_block_disabled" "
select
  name as bucket_name,
  block_public_acls,
  block_public_policy,
  ignore_public_acls,
  restrict_public_buckets
from
  aws_s3_bucket
where
  name like 'cloudguardian-data-%';
"

run_query "M05_s3_versioning_suspended" "
select
  name as bucket_name,
  versioning_enabled,
  versioning_mfa_delete
from
  aws_s3_bucket
where
  name like 'cloudguardian-data-%';
"

run_query "M10_s3_default_encryption" "
select
  name as bucket_name,
  server_side_encryption_configuration
from
  aws_s3_bucket
where
  name like 'cloudguardian-data-%';
"

# ------------------------------------------------------------
# VPC / Security Groups - M06, M07
# ------------------------------------------------------------
run_query "M06_sg_ssh_open_to_world" "
select
  group_name,
  group_id,
  ip_permission ->> 'FromPort' as from_port,
  ip_permission ->> 'ToPort' as to_port,
  ip_permission -> 'IpRanges' as ip_ranges
from
  aws_vpc_security_group,
  jsonb_array_elements(ip_permissions) as ip_permission
where
  ip_permission ->> 'FromPort' = '22'
  and ip_permission -> 'IpRanges' @> '[{\"CidrIp\": \"0.0.0.0/0\"}]';
"

run_query "M07_sg_mysql_open_to_world" "
select
  group_name,
  group_id,
  ip_permission ->> 'FromPort' as from_port,
  ip_permission ->> 'ToPort' as to_port,
  ip_permission -> 'IpRanges' as ip_ranges
from
  aws_vpc_security_group,
  jsonb_array_elements(ip_permissions) as ip_permission
where
  ip_permission ->> 'FromPort' = '3306'
  and ip_permission -> 'IpRanges' @> '[{\"CidrIp\": \"0.0.0.0/0\"}]';
"

# ------------------------------------------------------------
# RDS - M08, M09, M12
# ------------------------------------------------------------
run_query "M08_rds_publicly_accessible" "
select
  db_instance_identifier,
  publicly_accessible,
  vpc_id
from
  aws_rds_db_instance
where
  db_instance_identifier = 'cloudguardian-db';
"

run_query "M09_rds_storage_not_encrypted" "
select
  db_instance_identifier,
  storage_encrypted,
  kms_key_id
from
  aws_rds_db_instance
where
  db_instance_identifier = 'cloudguardian-db';
"

run_query "M12_rds_backup_disabled" "
select
  db_instance_identifier,
  backup_retention_period,
  preferred_backup_window
from
  aws_rds_db_instance
where
  db_instance_identifier = 'cloudguardian-db';
"

# ------------------------------------------------------------
# EC2 - M11
# ------------------------------------------------------------
run_query "M11_ec2_imdsv2_disabled" "
select
  instance_id,
  tags ->> 'Name' as name,
  metadata_options ->> 'HttpTokens' as http_tokens,
  metadata_options ->> 'HttpEndpoint' as http_endpoint,
  metadata_options ->> 'HttpPutResponseHopLimit' as hop_limit
from
  aws_ec2_instance
where
  tags ->> 'Name' = 'cloudguardian-web';
"

# ------------------------------------------------------------
# CloudTrail - logging / validation / region coverage
# ------------------------------------------------------------
run_query "CloudTrail_logging_validation_region_coverage" "
select
  name,
  is_logging,
  log_file_validation_enabled,
  is_multi_region_trail,
  include_global_service_events,
  kms_key_id,
  log_group_arn
from
  aws_cloudtrail_trail
where
  name = 'cloudguardian-trail';
"

run_query "CloudTrail_log_bucket_public_check" "
select
  t.name as trail_name,
  b.name as bucket_name,
  b.block_public_acls,
  b.block_public_policy
from
  aws_cloudtrail_trail t
  join aws_s3_bucket b on t.s3_bucket_name = b.name
where
  t.name = 'cloudguardian-trail';
"

echo ""
echo "=============================================="
echo " DONE. All CSVs saved in: $OUTDIR"
echo "=============================================="
ls -la "$OUTDIR"
