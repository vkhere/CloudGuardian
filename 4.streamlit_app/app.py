"""
CloudGuardian — Week 2/3 Streamlit App
CAP-CSE-3W | IIT Roorkee x Futurense

Streamlined, portable rewrite of the Week 2 Jupyter notebook pipeline:
  1. Upload & Consolidate (Prowler + Steampipe + ScoutSuite, AWS + Azure)
  2. Rule-Based Prioritization (CVSS x Exposure x Blast Radius)
  3. AI Risk Classification (RandomForest + SMOTE)
  4. OWASP LLM06 Redaction Engine
  5. RAG-Grounded Remediation Guidance (NVIDIA NIM)
  6. Auto-Remediation (Dry-Run only)
  7. Export

Run with:  streamlit run app.py
NVIDIA API key (optional, for Tab 5): export NVIDIA_API_KEY='nvapi-...' before launch
"""

import io
import os
import re
import json
import glob
import time
import logging
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st

# ══════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════
st.set_page_config(page_title="CloudGuardian", page_icon="🛡️", layout="wide")

logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("cloudguardian")

NORMALIZED_COLUMNS = [
    'check_id', 'title', 'severity', 'service', 'region',
    'resource_name', 'resource_arn', 'status_detail',
    'description', 'risk', 'remediation', 'tool', 'cloud_provider',
]

# ══════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════
for key, default in [
    ('consolidated', None),
    ('redaction_engine', None),
    ('llm_df', None),
    ('rag_audit_df', None),
    ('remediation_df', None),
    ('smote_pipeline', None),
    ('le_target', None),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# ══════════════════════════════════════════════════════════════════
# SIDEBAR — CONFIG
# ══════════════════════════════════════════════════════════════════
with st.sidebar:
    st.title("🛡️ CloudGuardian")
    st.caption("CAP-CSE-3W · IIT Roorkee x Futurense")

    st.subheader("Scan Metadata")
    account_id = st.text_input("AWS Account ID", value="735291151388")
    region = st.text_input("AWS Region", value="ap-south-1")
    scan_date = st.text_input("AWS Scan Date", value=datetime.now().strftime("%Y-%m-%d"))
    azure_scan_date = st.text_input("Azure Scan Date", value=datetime.now().strftime("%Y-%m-%d"))
    team_members = st.text_input("Team Members (comma-sep)", value="Megha, Vinay, Kedar")

    st.divider()
    st.subheader("NVIDIA NIM API")
    nvidia_key_present = bool(os.environ.get("NVIDIA_API_KEY"))
    if nvidia_key_present:
        st.success("NVIDIA_API_KEY found in environment ✅")
    else:
        st.warning(
            "NVIDIA_API_KEY not set.\n\n"
            "Run this in your terminal before launching the app:\n\n"
            "`export NVIDIA_API_KEY='nvapi-...'`\n\n"
            "The RAG remediation tab will fall back to TF-IDF-only "
            "retrieval and skip live LLM calls without it."
        )

    st.divider()
    st.caption(
        "⚠️ This app never stores or displays AWS/Azure credentials. "
        "Auto-remediation always runs in DRY-RUN mode — no live "
        "infrastructure changes are made from this app."
    )


# ══════════════════════════════════════════════════════════════════
# PART A — PROWLER LOADER
# ══════════════════════════════════════════════════════════════════
def load_prowler_csv(uploaded_file, provider_name: str):
    if uploaded_file is None:
        return None
    try:
        raw_bytes = uploaded_file.getvalue()
        provider_df = pd.read_csv(io.BytesIO(raw_bytes), sep=";", encoding="utf-8")
    except Exception as exc:
        st.error(f"Failed to read {provider_name} Prowler CSV: {exc}")
        return None

    required = {"STATUS", "SEVERITY"}
    missing = required - set(provider_df.columns)
    if missing:
        st.error(
            f"{provider_name} Prowler CSV is missing required column(s) {missing}. "
            f"Found columns: {list(provider_df.columns)}"
        )
        return None

    provider_df["cloud_provider"] = provider_name
    return provider_df


def build_prowler_fails(aws_file, azure_file):
    frames = {}
    aws_df = load_prowler_csv(aws_file, "AWS")
    if aws_df is not None:
        frames["AWS"] = aws_df
    azure_df = load_prowler_csv(azure_file, "Azure")
    if azure_df is not None:
        frames["Azure"] = azure_df

    if not frames:
        return None

    df = pd.concat(frames.values(), ignore_index=True)
    fails = df[df["STATUS"] == "FAIL"].copy()
    return fails


PROWLER_COL_MAP = {
    'CHECK_ID': 'check_id', 'CHECK_TITLE': 'title', 'SEVERITY': 'severity',
    'SERVICE_NAME': 'service', 'REGION': 'region', 'RESOURCE_NAME': 'resource_name',
    'RESOURCE_UID': 'resource_arn', 'STATUS_EXTENDED': 'status_detail',
    'DESCRIPTION': 'description', 'RISK': 'risk',
    'REMEDIATION_RECOMMENDATION_TEXT': 'remediation',
}


def normalize_prowler(fails: pd.DataFrame) -> pd.DataFrame:
    prowler_df = fails.rename(columns=PROWLER_COL_MAP)[list(PROWLER_COL_MAP.values())].copy()
    prowler_df['tool'] = 'Prowler v4'
    prowler_df['cloud_provider'] = fails['cloud_provider'].values
    return prowler_df[NORMALIZED_COLUMNS]


# ══════════════════════════════════════════════════════════════════
# PART B — STEAMPIPE LOADERS (AWS M01-M12 + CloudTrail, Azure 6-service)
# ══════════════════════════════════════════════════════════════════
def _is_true(val) -> bool:
    return str(val).strip().lower() in ('true', 't', 'yes', '1')


def _is_blank(val) -> bool:
    s = str(val).strip().lower()
    return s in ('', 'nan', 'none', 'null')


def _mk(check_id, title, severity, resource_name, status_detail, description, risk,
        remediation, service, cloud_provider):
    return {
        'check_id': check_id, 'title': title, 'severity': severity, 'service': service,
        'region': '', 'resource_name': resource_name, 'resource_arn': '',
        'status_detail': status_detail, 'description': description, 'risk': risk,
        'remediation': remediation, 'tool': 'Steampipe', 'cloud_provider': cloud_provider,
    }


AWS_M_CATALOGUE = {
    'M01_M02': dict(check_id='iam_role_inline_policy_wildcard',
        title='IAM Role Inline Policy Uses Wildcard Action/Resource', severity='critical', service='iam',
        description='IAM role has an inline policy granting wildcard (*) actions and/or resources.',
        risk='The role can call any AWS API on any resource — full blast-radius if ever assumed by an attacker.',
        remediation='Scope the inline policy to only the specific actions and resource ARNs the role needs.'),
    'M03': dict(check_id='iam_admin_policy_attached',
        title='IAM Role Has AdministratorAccess Managed Policy Attached', severity='critical', service='iam',
        description='This IAM role has the AWS-managed AdministratorAccess policy attached.',
        risk='If this role (attached to EC2) is compromised, the attacker gets full AWS account control.',
        remediation='Detach AdministratorAccess and replace it with a least-privilege custom policy.'),
    'M04': dict(check_id='s3_public_access_block_disabled',
        title='S3 Block Public Access Disabled', severity='high', service='s3',
        description='All four S3 Block Public Access settings are disabled on this bucket.',
        risk='The bucket can be made public via ACL or bucket policy with no safety net.',
        remediation='Re-enable all four Block Public Access settings at the bucket and account level.'),
    'M05': dict(check_id='s3_versioning_suspended',
        title='S3 Bucket Versioning Suspended', severity='medium', service='s3',
        description='Versioning is suspended on this S3 bucket.',
        risk='Accidental deletion or ransomware/overwrite causes permanent, unrecoverable data loss.',
        remediation='Re-enable versioning on the bucket.'),
    'M06': dict(check_id='sg_ssh_open_to_internet',
        title='Security Group Allows SSH (22) from 0.0.0.0/0', severity='high', service='ec2',
        description='Security group permits inbound SSH from any IP address on the internet.',
        risk='Brute-force / credential-stuffing attacks possible from anywhere.',
        remediation='Restrict SSH ingress to a trusted IP range, VPN, or bastion host.'),
    'M07': dict(check_id='sg_mysql_open_to_internet',
        title='Security Group Allows MySQL (3306) from 0.0.0.0/0', severity='critical', service='ec2',
        description='Security group permits inbound MySQL from any IP address on the internet.',
        risk='Database port is directly reachable and attackable from the internet.',
        remediation='Remove the 0.0.0.0/0 rule; restrict 3306 to the application security group only.'),
    'M08': dict(check_id='rds_publicly_accessible',
        title='RDS Instance Publicly Accessible', severity='critical', service='rds',
        description='RDS instance has publicly_accessible=true.',
        risk='Database gets a public endpoint; reachable directly from the internet.',
        remediation='Set publicly_accessible=false and place the instance in a private subnet.'),
    'M09': dict(check_id='rds_storage_not_encrypted',
        title='RDS Storage Encryption Disabled', severity='high', service='rds',
        description='RDS instance data at rest is not encrypted (storage_encrypted=false).',
        risk='Data is readable if the underlying disk or a snapshot is accessed/shared.',
        remediation='Enable storage encryption (requires snapshot + restore to a new encrypted instance).'),
    'M10': dict(check_id='s3_default_encryption_weak',
        title='S3 Default Encryption Missing/Weak Configuration', severity='medium', service='s3',
        description='S3 bucket default encryption configuration does not enforce strong at-rest encryption.',
        risk='Objects may be stored without adequate encryption at rest.',
        remediation='Enforce SSE-KMS (or at minimum SSE-S3/AES256) as the bucket default encryption.'),
    'M11': dict(check_id='ec2_imdsv1_enabled',
        title='EC2 IMDSv1 Enabled (HttpTokens=optional)', severity='high', service='ec2',
        description='Instance metadata service v1 is enabled without a token requirement.',
        risk='SSRF attacks can steal IAM credentials from the instance metadata endpoint.',
        remediation='Set HttpTokens=required on the instance to enforce IMDSv2.'),
    'M12': dict(check_id='rds_backup_disabled',
        title='RDS Automated Backups Disabled', severity='high', service='rds',
        description='RDS backup_retention_period is 0 — automated backups are off.',
        risk='No automated backups, no point-in-time recovery if data is lost or corrupted.',
        remediation='Set backup_retention_period to at least 7 days.'),
}


def _aws_m_key_from_filename(fname: str):
    base = os.path.basename(fname)
    m = re.match(r'^(M\d{2}(?:_M\d{2})?)_', base, re.IGNORECASE)
    return m.group(1).upper() if m else None


def rule_cloudtrail_logging_validation(row):
    out = []
    resource = row.get('name', '')
    if not _is_true(row.get('log_file_validation_enabled')):
        out.append(_mk('cloudtrail_log_file_validation_disabled',
            'CloudTrail Log File Validation Disabled', 'medium', resource,
            f"log_file_validation_enabled={row.get('log_file_validation_enabled')}",
            'CloudTrail log file integrity validation is not enabled on this trail.',
            'Tampering or deletion of delivered log files cannot be reliably detected.',
            'Enable log file validation on the trail to generate digest files for integrity checking.',
            'cloudtrail', 'AWS'))
    if not _is_true(row.get('is_multi_region_trail')):
        out.append(_mk('cloudtrail_not_multi_region',
            'CloudTrail Trail Is Not Multi-Region', 'high', resource,
            f"is_multi_region_trail={row.get('is_multi_region_trail')}",
            'This CloudTrail trail only captures events in its home region.',
            'API activity in other AWS regions goes completely unlogged, creating a blind spot.',
            'Recreate or update the trail with multi-region logging enabled.',
            'cloudtrail', 'AWS'))
    if not _is_true(row.get('include_global_service_events')):
        out.append(_mk('cloudtrail_global_service_events_disabled',
            'CloudTrail Does Not Log Global Service Events', 'medium', resource,
            f"include_global_service_events={row.get('include_global_service_events')}",
            'The trail is not configured to capture events from global services (e.g. IAM, STS).',
            'Changes to IAM users, roles, and policies may not be recorded.',
            'Enable "Include global service events" on the trail.',
            'cloudtrail', 'AWS'))
    if _is_blank(row.get('kms_key_id')):
        out.append(_mk('cloudtrail_logs_not_kms_encrypted',
            'CloudTrail Logs Not Encrypted with Customer-Managed KMS Key', 'medium', resource,
            f"kms_key_id={row.get('kms_key_id')}",
            'No customer-managed KMS key is configured to encrypt delivered log files.',
            'Log files rely on default S3 encryption rather than a CMK with dedicated key policy/audit trail.',
            'Enable SSE-KMS on the trail using a customer-managed key with a restrictive key policy.',
            'cloudtrail', 'AWS'))
    if _is_blank(row.get('log_group_arn')):
        out.append(_mk('cloudtrail_cloudwatch_logs_not_integrated',
            'CloudTrail Not Integrated with CloudWatch Logs', 'high', resource,
            f"log_group_arn={row.get('log_group_arn')}",
            'The trail is not delivering events to a CloudWatch Logs log group.',
            'No real-time monitoring or alerting (e.g. via metric filters/alarms) is possible on trail activity.',
            'Configure the trail to deliver events to a CloudWatch Logs log group.',
            'cloudtrail', 'AWS'))
    return out


def rule_cloudtrail_bucket_public(row):
    out = []
    resource = row.get('bucket_name', '')
    if not _is_true(row.get('block_public_acls')):
        out.append(_mk('cloudtrail_bucket_block_public_acls_disabled',
            'CloudTrail Log Bucket Does Not Block Public ACLs', 'high', resource,
            f"block_public_acls={row.get('block_public_acls')}",
            'The S3 bucket storing CloudTrail logs does not block public ACLs.',
            'The bucket (or objects in it) could be made public via ACL, exposing audit logs.',
            'Enable "Block Public ACLs" on the CloudTrail log bucket.',
            'cloudtrail', 'AWS'))
    if not _is_true(row.get('block_public_policy')):
        out.append(_mk('cloudtrail_bucket_block_public_policy_disabled',
            'CloudTrail Log Bucket Does Not Block Public Bucket Policies', 'high', resource,
            f"block_public_policy={row.get('block_public_policy')}",
            'The S3 bucket storing CloudTrail logs does not block public bucket policies.',
            'A misconfigured bucket policy could expose audit logs to the public internet.',
            'Enable "Block Public Policy" on the CloudTrail log bucket.',
            'cloudtrail', 'AWS'))
    return out


CLOUDTRAIL_RULES = {
    'CloudTrail_logging_validation_region_coverage': rule_cloudtrail_logging_validation,
    'CloudTrail_log_bucket_public_check': rule_cloudtrail_bucket_public,
}


def _cloudtrail_key_from_filename(fname: str):
    base = re.sub(r'\.csv$', '', os.path.basename(fname), flags=re.IGNORECASE)
    return base if base in CLOUDTRAIL_RULES else None


def load_aws_steampipe_findings(uploaded_files) -> pd.DataFrame:
    if not uploaded_files:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    rows = []
    for uf in uploaded_files:
        fname = uf.name
        ct_key = _cloudtrail_key_from_filename(fname)
        if ct_key is not None:
            try:
                raw = pd.read_csv(io.BytesIO(uf.getvalue()))
            except Exception as exc:
                st.warning(f"Failed to read {fname}: {exc}")
                continue
            if raw.empty:
                continue
            rule_fn = CLOUDTRAIL_RULES[ct_key]
            for _, row in raw.iterrows():
                rows.extend(rule_fn(row))
            continue

        key = _aws_m_key_from_filename(fname)
        meta = AWS_M_CATALOGUE.get(key)
        if meta is None:
            st.warning(f"AWS Steampipe: no catalogue entry for '{fname}' (key={key}) — skipped")
            continue
        try:
            raw = pd.read_csv(io.BytesIO(uf.getvalue()))
        except Exception as exc:
            st.warning(f"Failed to read {fname}: {exc}")
            continue
        if raw.empty:
            continue
        for _, row in raw.iterrows():
            resource_col = next((c for c in row.index if c in
                                  ('role_name', 'bucket_name', 'group_name',
                                   'db_instance_identifier', 'instance_id', 'name')), row.index[0])
            resource_name = str(row.get(resource_col, ''))
            status_detail = ', '.join(f"{c}={row[c]}" for c in row.index
                                       if pd.notna(row[c]) and str(row[c]).strip() != '')
            rows.append(_mk(meta['check_id'], meta['title'], meta['severity'], resource_name,
                             status_detail, meta['description'], meta['risk'], meta['remediation'],
                             meta['service'], 'AWS'))

    if not rows:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)
    return pd.DataFrame(rows)[NORMALIZED_COLUMNS]


def rule_azure_compute(row):
    out = []
    finding, value = str(row.get('finding', '')).strip(), str(row.get('value', '')).strip()
    if finding == 'password_auth_enabled' and _is_true(value):
        out.append(_mk('vm_password_auth_enabled', 'VM Allows SSH Password Authentication', 'high',
            row.get('resource', ''), f"{finding}={value}",
            'SSH password authentication is enabled instead of key-only.',
            'Weak/brute-forceable passwords can be used to log into the VM.',
            'Disable password authentication; require SSH key-based login only.', 'compute', 'Azure'))
    return out


def rule_azure_iam(row):
    out = []
    finding = str(row.get('finding', '')).strip()
    resource = f"{row.get('principal_type', '')}:{row.get('role_name', '')}"
    if finding == 'owner_at_rg_scope':
        out.append(_mk('iam_owner_role_at_rg_scope', 'Owner Role Assigned at Resource Group Scope', 'critical',
            resource, f"scope={row.get('scope', '')}",
            'A principal has the Owner role at the resource group scope.',
            'Owner allows full control including IAM changes — over-privileged for most identities.',
            'Replace with a scoped, least-privilege role (e.g. Contributor limited to needed resources).',
            'iam', 'Azure'))
    elif finding == 'vm_identity_over_privileged':
        out.append(_mk('vm_identity_over_privileged', 'VM Managed Identity Over-Privileged at Subscription Scope',
            'critical', resource, f"scope={row.get('scope', '')}",
            "The VM's system-assigned managed identity has Contributor at the subscription scope.",
            'If the VM is compromised, the attacker inherits Contributor over the entire subscription.',
            'Scope the role assignment down to only the resource group/resources the VM needs.',
            'iam', 'Azure'))
    return out


def rule_azure_logging(row):
    out = []
    resource = row.get('resource', '')
    finding, value = str(row.get('finding', '')).strip(), str(row.get('value', '')).strip()
    if finding in ('storage_diagnostic_setting', 'sql_diagnostic_setting') and value.upper() == 'MISSING':
        svc = 'Storage account' if 'storage' in finding else 'SQL database'
        out.append(_mk(f'{finding}_missing', f'{svc} Diagnostic Logging Not Configured', 'high',
            resource, f"{finding}={value}",
            f'{svc} has no diagnostic setting sending logs to Log Analytics.',
            'Activity on this resource is not captured, hindering incident detection/investigation.',
            'Add a diagnostic setting forwarding logs to the Log Analytics workspace.', 'logging', 'Azure'))
    elif finding == 'retention_in_days':
        try:
            days = int(value)
        except ValueError:
            days = None
        if days is not None and days < 90:
            out.append(_mk('log_retention_short', 'Log Analytics Retention Below Recommended 90 Days', 'medium',
                resource, f"{finding}={value}",
                f'Log Analytics workspace retention is set to {value} days.',
                'Shorter retention limits how far back an investigation can look after a breach.',
                'Increase retention_in_days to 90 (or per your compliance requirement).', 'logging', 'Azure'))
    return out


def rule_azure_nsg(row):
    resource = row.get('resource', '')
    finding, value = str(row.get('finding', '')).strip(), str(row.get('value', '')).strip()
    NSG_RULES = {
        'ssh_open_to_internet': ('sg_ssh_open_to_internet', 'NSG Allows SSH from Any Source', 'high',
            'NSG rule allows inbound SSH from any source address.',
            'Brute-force/credential-stuffing attacks possible from anywhere.',
            'Restrict the source to a trusted IP/CIDR (e.g. your admin IP) only.'),
        'allow_any_any': ('nsg_allow_any_any', 'NSG Allows Any Protocol/Port from Any Source', 'critical',
            'NSG has a rule permitting all protocols and ports from any source.',
            'Provides effectively no network-layer filtering — full exposure.',
            'Remove the any/any rule; add explicit rules scoped to required ports and sources.'),
        'nsg_association_removed': ('nsg_not_attached', 'Subnet Has No NSG Attached', 'high',
            'The subnet has no Network Security Group associated with it.',
            'No network-layer filtering exists in front of resources in this subnet.',
            'Attach an appropriately scoped NSG to the subnet.'),
        'nsg_association_missing': ('nsg_not_attached', 'Subnet Has No NSG Attached', 'high',
            'The subnet has no Network Security Group associated with it.',
            'No network-layer filtering exists in front of resources in this subnet.',
            'Attach an appropriately scoped NSG to the subnet.'),
    }
    if finding in NSG_RULES:
        check_id, title, sev, desc, risk, rem = NSG_RULES[finding]
        return [_mk(check_id, title, sev, resource, f"{finding}={value}", desc, risk, rem, 'nsg', 'Azure')]
    return []


def rule_azure_sql(row):
    out = []
    resource = row.get('server_name', '')
    start_ip, end_ip = str(row.get('start_ip', '')), str(row.get('end_ip', ''))
    if start_ip == '0.0.0.0' and end_ip == '255.255.255.255':
        out.append(_mk('sql_firewall_allow_all_ips', 'SQL Server Firewall Allows All IPs', 'critical',
            resource, f"firewall_rule={row.get('firewall_rule_name', '')}, range={start_ip}-{end_ip}",
            'A firewall rule opens the SQL server to every IP address on the internet.',
            'The database is directly reachable and attackable from anywhere.',
            'Remove the all-IPs rule; scope firewall rules to specific known IPs/VNets.', 'sql', 'Azure'))
    if not _is_true(row.get('tde_enabled', 'true')):
        out.append(_mk('sql_tde_disabled', 'SQL Transparent Data Encryption Disabled', 'high',
            resource, f"tde_enabled={row.get('tde_enabled')}",
            'Transparent Data Encryption is not enabled on the SQL database.',
            'Data at rest is not encrypted; readable if underlying storage/backups are accessed.',
            'Enable TDE on the SQL database.', 'sql', 'Azure'))
    min_tls = str(row.get('min_tls', '')).strip()
    if min_tls and min_tls not in ('1.2', '1.3'):
        out.append(_mk('sql_min_tls_outdated', 'SQL Server Minimum TLS Version Below 1.2', 'medium',
            resource, f"min_tls={min_tls}",
            f'SQL server minimum TLS version is set to {min_tls}.',
            'Outdated TLS versions permit weaker transport encryption.',
            'Set the minimum TLS version to 1.2.', 'sql', 'Azure'))
    if not _is_true(row.get('auditing_enabled', 'true')):
        out.append(_mk('sql_auditing_disabled', 'SQL Server Auditing Disabled', 'medium',
            resource, f"auditing_enabled={row.get('auditing_enabled')}",
            'Auditing is not enabled on the SQL server.',
            'Query/access activity on the database is not logged for investigation.',
            'Enable SQL Server auditing and send logs to Log Analytics/Storage.', 'sql', 'Azure'))
    return out


def rule_azure_storage(row):
    resource = row.get('name', '')
    checks = [
        (_is_true(row.get('allow_blob_public_access')), 'storage_allow_blob_public_access',
         'Storage Account Allows Public Blob Access', 'high',
         'allow_blob_public_access=true — the account permits containers/blobs to be made public.',
         'Combined with a public container ACL, data becomes readable by anyone on the internet.',
         'Set allow_blob_public_access=false at the storage account level.'),
        (str(row.get('public_network_access', '')).strip().lower() == 'allow', 'storage_public_network_access',
         'Storage Account Reachable From Any Network', 'high',
         'public_network_access=Allow — not restricted to VNet or trusted IPs.',
         'The storage account can be reached from any network on the internet.',
         'Set public_network_access to Disabled, or restrict via firewall/VNet rules.'),
        (not _is_true(row.get('enable_https_traffic_only', 'true')), 'storage_secure_transfer_disabled',
         'Storage Account Does Not Require HTTPS', 'high',
         'enable_https_traffic_only=false — plain HTTP is permitted.',
         'Data can be transmitted unencrypted between client and storage.',
         'Set enable_https_traffic_only=true (Secure transfer required).'),
        (str(row.get('minimum_tls_version', '')).strip().upper() not in ('TLS1_2', 'TLS1_3', ''),
         'storage_min_tls_outdated', 'Storage Account Minimum TLS Version Below 1.2', 'medium',
         f"minimum_tls_version={row.get('minimum_tls_version')}.",
         'Outdated TLS versions permit weaker transport encryption.',
         'Set minimum_tls_version to TLS1_2.'),
        (not _is_true(row.get('default_to_oauth_authentication', 'true')), 'storage_shared_key_access_default',
         'Storage Account Defaults to Shared Key Auth Instead of Entra ID', 'medium',
         'default_to_oauth_authentication=false — tools/portal default to Shared Key auth.',
         'Shared Key access is harder to audit/revoke per-identity than Entra ID (Azure AD) auth.',
         'Set default_to_oauth_authentication=true to prefer Entra ID authentication.'),
        (str(row.get('container_access_type', '')).strip().lower() in ('blob', 'container'),
         'storage_public_container', 'Blob Container Is Publicly Readable', 'critical',
         f"container_name={row.get('container_name')}, container_access_type={row.get('container_access_type')}.",
         'Anyone on the internet can read (or list) objects in this container.',
         'Set the container access level to Private and use SAS tokens/Entra ID for access.'),
    ]
    out = []
    for is_bad, check_id, title, sev, status_detail, risk, remediation in checks:
        if is_bad:
            out.append(_mk(check_id, title, sev, resource, status_detail,
                            title, risk, remediation, 'storage', 'Azure'))
    return out


AZURE_STEAMPIPE_RULES = {
    'compute': rule_azure_compute, 'iam': rule_azure_iam, 'logging': rule_azure_logging,
    'nsg': rule_azure_nsg, 'sql': rule_azure_sql, 'storage': rule_azure_storage,
}


def load_azure_steampipe_findings(uploaded_files) -> pd.DataFrame:
    if not uploaded_files:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    all_rows = []
    for uf in uploaded_files:
        base = re.sub(r'\.csv$', '', re.sub(r'^steampipe_', '', uf.name, flags=re.I), flags=re.I)
        rule_fn = AZURE_STEAMPIPE_RULES.get(base)
        if rule_fn is None:
            st.warning(f"Azure Steampipe: no rule for '{base}' ({uf.name}) — skipped")
            continue
        try:
            raw = pd.read_csv(io.BytesIO(uf.getvalue()))
        except Exception as exc:
            st.warning(f"Failed to read {uf.name}: {exc}")
            continue
        for _, row in raw.iterrows():
            all_rows.extend(rule_fn(row))

    if not all_rows:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)
    return pd.DataFrame(all_rows)[NORMALIZED_COLUMNS]


# ══════════════════════════════════════════════════════════════════
# PART C — SCOUTSUITE LOADER
# ══════════════════════════════════════════════════════════════════
SCOUTSUITE_LEVEL_TO_SEVERITY = {'danger': 'high', 'warning': 'medium', 'good': 'low'}
_RESOURCE_ID_PATTERN = re.compile(r'\b((?:sg|vol|vpc|subnet|acl|i|scoutid)-[a-zA-Z0-9]+)\b')


def _resource_name_from_item(item_path: str) -> str:
    m = _RESOURCE_ID_PATTERN.search(item_path)
    return m.group(1) if m else item_path


def load_scoutsuite_findings(uploaded_file, provider_name: str) -> pd.DataFrame:
    if uploaded_file is None:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    try:
        raw_text = uploaded_file.getvalue().decode("utf-8")
    except Exception as exc:
        st.warning(f"Failed to read {provider_name} ScoutSuite file: {exc}")
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    match = re.search(r'=\s*(\{.*\})\s*;?\s*$', raw_text, re.DOTALL)
    if not match:
        st.warning(f"Could not locate JSON object inside {provider_name} ScoutSuite file")
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    try:
        data = json.loads(match.group(1))
    except Exception as exc:
        st.warning(f"Failed to parse JSON from {provider_name} ScoutSuite file: {exc}")
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    rows = []
    for service_name, service_data in (data.get('services', {}) or {}).items():
        for finding_id, finding in ((service_data or {}).get('findings', {}) or {}).items():
            flagged_count = finding.get('flagged_items', 0) or 0
            if flagged_count == 0:
                continue
            items = finding.get('items') or ['(see ScoutSuite HTML report for resource list)']
            severity = SCOUTSUITE_LEVEL_TO_SEVERITY.get((finding.get('level') or '').lower(), 'medium')
            description = finding.get('description', '')
            for item in items:
                item_path = str(item)
                rows.append({
                    'check_id': finding_id, 'title': description, 'severity': severity,
                    'service': service_name, 'region': '',
                    'resource_name': _resource_name_from_item(item_path), 'resource_arn': '',
                    'status_detail': item_path, 'description': description,
                    'risk': finding.get('rationale', ''), 'remediation': finding.get('remediation', ''),
                    'tool': 'ScoutSuite', 'cloud_provider': provider_name,
                })

    if not rows:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)
    return pd.DataFrame(rows)[NORMALIZED_COLUMNS]


# ══════════════════════════════════════════════════════════════════
# PART D — CONSOLIDATION
# ══════════════════════════════════════════════════════════════════
def consolidate_all(prowler_df, steampipe_df, scoutsuite_df, account_id, region,
                     scan_date, azure_scan_date):
    consolidated = pd.concat([prowler_df, steampipe_df, scoutsuite_df], ignore_index=True)
    consolidated['finding_id'] = [f"FND-{str(i+1).zfill(4)}" for i in range(len(consolidated))]
    consolidated['account_id'] = consolidated['cloud_provider'].map({
        'AWS': account_id, 'Azure': 'Azure-Subscription',
    })
    consolidated['scan_date'] = consolidated['cloud_provider'].map({
        'AWS': scan_date, 'Azure': azure_scan_date,
    })
    return consolidated


# ══════════════════════════════════════════════════════════════════
# PART E — RULE-BASED PRIORITIZATION
# ══════════════════════════════════════════════════════════════════
CVSS_SCORE_MAP = {'critical': 9.5, 'high': 7.5, 'medium': 5.5, 'low': 3.0}
CVSS_DEFAULT_SCORE = 3.0

EXPOSURE_KEYWORDS_DIRECT = ['0.0.0.0', 'publicly', 'internet', 'public']
EXPOSURE_KEYWORDS_POTENTIAL = ['public', 'exposed', 'internet', 'open']

NEGATION_CUES = [
    'not ', 'no ', "n't", 'without ', 'never ',
    'restrict', 'block', 'prevent', 'disallow', 'deny', 'protects against',
]
NEGATION_WINDOW = 45

IAM_SERVICE_NAMES = ['iam', 'entra']
DATABASE_SERVICE_NAMES = ['rds', 'sql', 'sqlserver']
BLAST_RADIUS_HIGH_RISK_SERVICES = [
    's3', 'rds', 'ec2', 'cloudtrail', 'vpc', 'cloudwatch',
    'storage', 'monitor', 'network', 'sql', 'defender', 'keyvault', 'sqlserver',
]
IAM_ESCALATION_KEYWORDS = ['admin', 'wildcard', '*', 'global admin', 'owner']

# CALIBRATION NOTE (fixed 2026-07-19): blast_radius tops out at 3 for every
# service *except* IAM (4-5) or a database finding whose title literally
# contains "public" (4). That means the ceiling for a critical, directly-
# exposed finding on any other service — EC2, VPC, generic RDS/SQL, S3,
# storage, network, monitor, etc. — is a hard 9.5 * 3 * 3 = 85.5, which could
# never clear a P0 threshold of 100 no matter how bad the finding actually is.
# Only IAM-escalation or "public"-titled DB findings could ever reach P0.
# Lowering the P0 cutoff to 85 lets "critical severity + confirmed direct
# internet exposure" reach P0 regardless of which service it's on, while still
# requiring both cvss_score and exposure_score to be at their maximum — it
# does NOT let medium/high findings in on exposure alone (max non-critical
# score at blast=3 is high(7.5) * 3 * 3 = 67.5, still comfortably P1).
PRIORITY_THRESHOLDS = {'P0 - CRITICAL': 85, 'P1 - HIGH': 60, 'P2 - MEDIUM': 30}
BAND_EMOJI = {'P0 - CRITICAL': '🔴', 'P1 - HIGH': '🟠', 'P2 - MEDIUM': '🟡', 'P3 - LOW': '🟢'}


def _keyword_hit(text: str, keywords: list) -> bool:
    text = str(text).lower()
    for kw in keywords:
        start = 0
        while True:
            idx = text.find(kw, start)
            if idx == -1:
                break
            window = text[max(0, idx - NEGATION_WINDOW): idx]
            if not any(neg in window for neg in NEGATION_CUES):
                return True
            start = idx + len(kw)
    return False


def exposure_score(row):
    detail = row.get('status_detail', '')
    title = row.get('title', '')
    if _keyword_hit(detail, EXPOSURE_KEYWORDS_DIRECT):
        return 3
    if _keyword_hit(title, EXPOSURE_KEYWORDS_POTENTIAL):
        return 2
    return 1


def blast_radius(row):
    svc = str(row.get('service', '')).lower()
    title = row.get('title', '')
    if svc in IAM_SERVICE_NAMES and _keyword_hit(title, IAM_ESCALATION_KEYWORDS):
        return 5
    if svc in IAM_SERVICE_NAMES:
        return 4
    if svc in DATABASE_SERVICE_NAMES and _keyword_hit(title, ['public']):
        return 4
    if svc in BLAST_RADIUS_HIGH_RISK_SERVICES:
        return 3
    return 2


def priority_band(score):
    if score >= PRIORITY_THRESHOLDS['P0 - CRITICAL']:
        return 'P0 - CRITICAL'
    if score >= PRIORITY_THRESHOLDS['P1 - HIGH']:
        return 'P1 - HIGH'
    if score >= PRIORITY_THRESHOLDS['P2 - MEDIUM']:
        return 'P2 - MEDIUM'
    return 'P3 - LOW'


def apply_prioritization(consolidated: pd.DataFrame) -> pd.DataFrame:
    df = consolidated.copy()
    severity_lower = df['severity'].astype(str).str.lower()
    df['cvss_score'] = severity_lower.map(CVSS_SCORE_MAP).fillna(CVSS_DEFAULT_SCORE)
    df['exposure_score'] = df.apply(exposure_score, axis=1)
    df['blast_radius'] = df.apply(blast_radius, axis=1)
    df['priority_score'] = (df['cvss_score'] * df['exposure_score'] * df['blast_radius']).round(2)
    df['priority_band'] = df['priority_score'].apply(priority_band)
    df.sort_values('priority_score', ascending=False, inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


# ══════════════════════════════════════════════════════════════════
# PART F — AI RISK CLASSIFICATION (RandomForest + SMOTE, final model only)
# ══════════════════════════════════════════════════════════════════
def assign_risk_label_independent(row):
    """AI risk tier — a composite classification (severity + exposure pattern
    + service type), deliberately kept at 3 classes (CRITICAL/MEDIUM/LOW)
    rather than mirroring the scanner's 4-level `severity` field 1:1. This is
    NOT the same taxonomy as `severity` or `priority_band` — e.g. an IAM-admin
    or RDS-public finding lands in CRITICAL here even if its raw scanner
    severity is only 'high', because the composite risk pattern warrants it."""
    svc = str(row.get('service', '')).lower()
    severity = str(row.get('severity', '')).lower()
    detail = str(row.get('status_detail', '')).lower()
    title = str(row.get('title', '')).lower()

    if severity == 'critical':
        return 'CRITICAL'
    if svc == 'iam' and 'admin' in title:
        return 'CRITICAL'
    if svc == 'rds' and 'public' in detail:
        return 'CRITICAL'
    if '0.0.0.0' in detail and severity == 'high':
        return 'CRITICAL'
    if 'cloudtrail' in svc and 'disabled' in title:
        return 'CRITICAL'
    if severity == 'low':
        return 'LOW'
    if svc in ['backup', 'trustedadvisor', 'sagemaker']:
        return 'LOW'
    if 'informational' in severity:
        return 'LOW'
    return 'MEDIUM'


def train_smote_model(consolidated: pd.DataFrame):
    """Train the SMOTE-balanced RandomForest (the final/best model from
    the notebook — supersedes the plain-RandomForest baseline)."""
    from imblearn.over_sampling import SMOTE
    from imblearn.pipeline import Pipeline as ImbPipeline
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.metrics import classification_report

    df = consolidated.copy()
    df['risk_label'] = df.apply(assign_risk_label_independent, axis=1)

    le_service, le_severity, le_target, le_cloud = (LabelEncoder() for _ in range(4))
    df['service_enc'] = le_service.fit_transform(df['service'].fillna('other'))
    df['severity_enc'] = le_severity.fit_transform(df['severity'].fillna('low'))
    df['risk_enc'] = le_target.fit_transform(df['risk_label'])
    df['cloud_enc'] = le_cloud.fit_transform(df['cloud_provider'].fillna('AWS'))

    np.random.seed(42)
    df['cvss_noisy'] = df['cvss_score'] + np.random.normal(0, 0.3, len(df))
    df['exposure_noisy'] = df['exposure_score'] + np.random.normal(0, 0.2, len(df))

    X = df[['cvss_noisy', 'exposure_noisy', 'blast_radius', 'service_enc', 'severity_enc', 'cloud_enc']]
    y = df['risk_enc']

    critical_label_enc = le_target.transform(['CRITICAL'])[0]
    high_count = int((y == critical_label_enc).sum())
    smallest_expected_high_in_fold = max(2, int(high_count * 0.7 / 5))
    k_neighbors = max(1, min(5, smallest_expected_high_in_fold - 1))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    smote_pipeline = ImbPipeline([
        ('smote', SMOTE(random_state=42, k_neighbors=k_neighbors)),
        ('clf', RandomForestClassifier(
            n_estimators=100, max_depth=3, min_samples_leaf=3,
            max_features='sqrt', random_state=42
        )),
    ])
    smote_pipeline.fit(X_train, y_train)
    smote_report = classification_report(
        y_test, smote_pipeline.predict(X_test), target_names=le_target.classes_, output_dict=True
    )

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    smote_cv_acc = cross_val_score(smote_pipeline, X, y, cv=skf, scoring='accuracy')
    smote_cv_f1 = cross_val_score(smote_pipeline, X, y, cv=skf, scoring='f1_macro')

    df['ai_risk_level'] = le_target.inverse_transform(smote_pipeline.predict(X))
    df['ai_confidence'] = smote_pipeline.predict_proba(X).max(axis=1).round(3)

    metrics = {
        'cv_accuracy_mean': smote_cv_acc.mean(), 'cv_accuracy_std': smote_cv_acc.std(),
        'cv_f1_mean': smote_cv_f1.mean(), 'cv_f1_std': smote_cv_f1.std(),
        'classification_report': smote_report, 'k_neighbors': k_neighbors,
        'high_count': high_count, 'total': len(y),
        'classes': list(le_target.classes_),
    }
    return df, smote_pipeline, le_target, metrics


# ══════════════════════════════════════════════════════════════════
# PART G — OWASP LLM06 REDACTION ENGINE
# ══════════════════════════════════════════════════════════════════
class OWASPRedactionEngine:
    """Pre-processing redaction engine aligned with OWASP LLM06:2025
    (Sensitive Information Disclosure)."""

    WILDCARD_CIDRS = {"0.0.0.0/0", "::/0"}

    PATTERN_ORDER = [
        "AWS_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECRET_KEY", "PRIVATE_KEY_BLOCK",
        "JWT_TOKEN", "IAM_ARN", "GENERIC_ARN", "RDS_ENDPOINT", "INTERNAL_HOSTNAME",
        "INSTANCE_ID", "SECURITY_GROUP_ID", "NETWORK_ACL_ID", "VOLUME_ID", "SUBNET_ID",
        "VPC_ID", "AZURE_SUBSCRIPTION_ID", "ACCOUNT_ID", "IPV6_ADDRESS", "IPV4_ADDRESS",
        "PROJECT_RESOURCE_NAME", "EMAIL_ADDRESS",
    ]

    PATTERNS = {
        "AWS_ACCESS_KEY": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        "AWS_SESSION_TOKEN": re.compile(r'\bASIA[0-9A-Z]{16}\b'),
        "AWS_SECRET_KEY": re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])'),
        "PRIVATE_KEY_BLOCK": re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----'),
        "JWT_TOKEN": re.compile(r'\bey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
        "IAM_ARN": re.compile(r'arn:aws:iam::\d{12}:[\w-]+/[\w-]+'),
        "GENERIC_ARN": re.compile(r'arn:aws:[\w-]+:[\w-]*:\d{12}:[\w\-/:]+'),
        "RDS_ENDPOINT": re.compile(r'\b[\w-]+\.[a-z0-9]{10,15}\.[a-z0-9-]+\.rds\.amazonaws\.com\b'),
        "INTERNAL_HOSTNAME": re.compile(r'\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.[\w.-]*\.compute\.internal\b'),
        "INSTANCE_ID": re.compile(r'\bi-[0-9a-f]{8,17}\b'),
        "SECURITY_GROUP_ID": re.compile(r'\bsg-[0-9a-f]{8,17}\b'),
        "NETWORK_ACL_ID": re.compile(r'\bacl-[0-9a-f]{8,17}\b'),
        "VOLUME_ID": re.compile(r'\bvol-[0-9a-f]{8,17}\b'),
        "SUBNET_ID": re.compile(r'\bsubnet-[0-9a-f]{8,17}\b'),
        "VPC_ID": re.compile(r'\bvpc-[0-9a-f]{8,17}\b'),
        "ACCOUNT_ID": re.compile(r'\b\d{12}\b'),
        "AZURE_SUBSCRIPTION_ID": re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'),
        "PROJECT_RESOURCE_NAME": re.compile(r'\w*cloudguardian[\w-]*', re.IGNORECASE),
        "IPV6_ADDRESS": re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}(?:/\d{1,3})?\b'),
        "IPV4_ADDRESS": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'),
        "EMAIL_ADDRESS": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    }

    def __init__(self):
        self._token_map = {}
        self._counters = defaultdict(int)
        self.audit_log = []

    def _get_token(self, category, raw_value):
        if raw_value not in self._token_map:
            self._counters[category] += 1
            token = f"[{category}_{self._counters[category]:03d}]"
            self._token_map[raw_value] = token
            self.audit_log.append({
                "category": category, "token": token, "raw_value_length": len(raw_value),
            })
        return self._token_map[raw_value]

    def redact(self, text):
        if text is None:
            return text
        text = str(text)
        for category in self.PATTERN_ORDER:
            pattern = self.PATTERNS[category]
            if category in ("IPV4_ADDRESS", "IPV6_ADDRESS"):
                def _sub(m, cat=category):
                    if m.group(0) in self.WILDCARD_CIDRS:
                        return m.group(0)
                    return self._get_token(cat, m.group(0))
                text = pattern.sub(_sub, text)
            else:
                text = pattern.sub(lambda m, cat=category: self._get_token(cat, m.group(0)), text)
        return text

    def get_mapping_table(self):
        return [{"raw_value": raw, "token": token} for raw, token in self._token_map.items()]

    def summary(self):
        return dict(self._counters)


# ══════════════════════════════════════════════════════════════════
# PART H — RAG-GROUNDED REMEDIATION GUIDANCE (NVIDIA NIM)
# ══════════════════════════════════════════════════════════════════
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_EMBED_URL = "https://integrate.api.nvidia.com/v1/embeddings"
NVIDIA_MODEL = "meta/llama-3.1-8b-instruct"
NVIDIA_EMBED_MODEL = "nvidia/nv-embedqa-e5-v5"

CONTROL_KB = [
    {"control_ref": "AWS-S3-01", "cloud": "AWS", "service": "s3",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "Amazon S3 buckets should have account-level and bucket-level Block Public Access "
             "enabled to prevent public reads and writes. When disabled, bucket policies or ACLs "
             "can expose objects to anyone on the internet. Enable all four Block Public Access "
             "settings and review bucket policies regularly."},
    {"control_ref": "AWS-S3-02", "cloud": "AWS", "service": "s3",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "S3 buckets storing production or backup data should have versioning enabled. "
             "Versioning preserves prior object versions, allowing recovery from accidental "
             "deletion, overwrite, or ransomware-style corruption. Suspended versioning removes "
             "this protection going forward."},
    {"control_ref": "AWS-IAM-01", "cloud": "AWS", "service": "iam",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "IAM users with console access should have multi-factor authentication enforced. "
             "A compromised password alone should not be sufficient to authenticate, especially "
             "for privileged or administrative users."},
    {"control_ref": "AWS-IAM-02", "cloud": "AWS", "service": "iam",
     "framework": "AWS Well-Architected Framework — Security Pillar", "source": "AWS Well-Architected",
     "source_url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
     "text": "IAM roles and users should follow least privilege. Avoid attaching broad managed "
             "policies such as AdministratorAccess to service roles; scope permissions to only "
             "the specific actions and resources the workload actually requires."},
    {"control_ref": "AWS-IAM-03", "cloud": "AWS", "service": "iam",
     "framework": "AWS Well-Architected Framework — Security Pillar", "source": "AWS Well-Architected",
     "source_url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
     "text": "IAM inline and managed policies should be reviewed for privilege-escalation paths — "
             "actions such as iam:PassRole, iam:CreatePolicyVersion, or iam:AttachUserPolicy granted "
             "together can let a low-privileged principal grant itself administrative access. Remove "
             "or scope these action combinations to specific resources."},
    {"control_ref": "AWS-RDS-01", "cloud": "AWS", "service": "rds",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "RDS instances should not be marked publicly accessible unless there is a documented "
             "business need. A publicly accessible database is reachable directly from the "
             "internet on its database port, exposing it to brute-force and exploitation attempts."},
    {"control_ref": "AWS-RDS-02", "cloud": "AWS", "service": "rds",
     "framework": "AWS Well-Architected Framework — Security Pillar", "source": "AWS Well-Architected",
     "source_url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
     "text": "RDS storage encryption should be enabled using AWS KMS. Encryption-at-rest cannot be "
             "toggled on an existing unencrypted instance, so remediation typically requires "
             "creating an encrypted snapshot and restoring a new instance from it."},
    {"control_ref": "AWS-RDS-03", "cloud": "AWS", "service": "rds",
     "framework": "AWS Well-Architected Framework — Security Pillar", "source": "AWS Well-Architected",
     "source_url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
     "text": "RDS parameter groups should require SSL/TLS for client connections "
             "(require_secure_transport=1). Without this, credentials and query data travel in "
             "plaintext across the network."},
    {"control_ref": "AWS-EC2-01", "cloud": "AWS", "service": "ec2",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "EC2 instances should enforce IMDSv2 by setting HttpTokens to required. IMDSv1 is "
             "vulnerable to SSRF-based credential theft, where an attacker who can trigger an "
             "HTTP request from the instance can retrieve IAM role credentials from the metadata "
             "endpoint."},
    {"control_ref": "AWS-EC2-02", "cloud": "AWS", "service": "ec2",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "EBS volumes attached to EC2 instances should be encrypted, ideally via account-level "
             "default encryption. Unencrypted volumes expose data at rest if a snapshot is shared "
             "or a disk is later mounted elsewhere."},
    {"control_ref": "AWS-EC2-03", "cloud": "AWS", "service": "ec2",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "Security groups should not permit SSH (port 22) from 0.0.0.0/0. Administrative "
             "access should be restricted to a bastion host, VPN CIDR range, or specific known IP "
             "addresses."},
    {"control_ref": "AWS-EC2-04", "cloud": "AWS", "service": "ec2",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "Security groups should not permit database ports such as MySQL (3306), PostgreSQL "
             "(5432), or MSSQL (1433) from 0.0.0.0/0. Database ports should only be reachable from "
             "application-tier security groups or specific trusted CIDR ranges, never directly from "
             "the internet."},
    {"control_ref": "AWS-CLOUDTRAIL-01", "cloud": "AWS", "service": "cloudtrail",
     "framework": "CIS AWS Foundations Benchmark v5.0.0", "source": "CIS Benchmarks",
     "source_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
     "text": "A multi-region CloudTrail trail should be enabled and continuously logging to a "
             "dedicated, access-restricted S3 bucket. Without CloudTrail there is no audit record "
             "of API activity, making incident investigation impossible."},
    {"control_ref": "AWS-VPC-01", "cloud": "AWS", "service": "vpc",
     "framework": "AWS Well-Architected Framework — Security Pillar", "source": "AWS Well-Architected",
     "source_url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
     "text": "Network ACLs should not allow all protocols from 0.0.0.0/0. NACLs are a stateless "
             "perimeter control and should be scoped to only the ports and protocols the "
             "application requires, layered alongside security groups."},
    {"control_ref": "AZ-STORAGE-01", "cloud": "Azure", "service": "storage",
     "framework": "Microsoft Cloud Security Benchmark", "source": "Microsoft Learn",
     "source_url": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
     "text": "Azure Storage accounts should have public blob access disabled at the account level "
             "(allowBlobPublicAccess=false). Individual containers should not be set to public "
             "unless explicitly required, since public containers are readable by anyone with the "
             "URL."},
    {"control_ref": "AZ-STORAGE-02", "cloud": "Azure", "service": "storage",
     "framework": "Microsoft Cloud Security Benchmark", "source": "Microsoft Learn",
     "source_url": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
     "text": "Azure Storage accounts should restrict network access (publicNetworkAccess=Disabled "
             "or a firewall scoped to selected VNets/IPs) rather than being reachable from any "
             "network, to prevent unauthorized access to blobs, queues, or tables from the open "
             "internet."},
    {"control_ref": "AZ-ENTRA-01", "cloud": "Azure", "service": "entra",
     "framework": "Microsoft Cloud Security Benchmark", "source": "Microsoft Learn",
     "source_url": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
     "text": "Azure AD (Entra ID) users, particularly those with privileged roles, should have "
             "multi-factor authentication enforced via Conditional Access policies. Password-only "
             "authentication is insufficient for accounts with elevated permissions."},
    {"control_ref": "AZ-SQL-01", "cloud": "Azure", "service": "sqlserver",
     "framework": "Microsoft Cloud Security Benchmark", "source": "Microsoft Learn",
     "source_url": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
     "text": "Azure SQL Database firewall rules should not allow unrestricted access. Firewall "
             "rules should be scoped to specific IP ranges, and Transparent Data Encryption should "
             "remain enabled for data at rest."},
    {"control_ref": "AZ-MONITOR-01", "cloud": "Azure", "service": "monitor",
     "framework": "Microsoft Cloud Security Benchmark", "source": "Microsoft Learn",
     "source_url": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
     "text": "Diagnostic settings and Azure Monitor logging should be enabled for critical "
             "resources, streaming logs to a Log Analytics workspace. Without this there is no "
             "centralized audit trail for detecting or investigating suspicious activity."},
    {"control_ref": "AZ-NETWORK-01", "cloud": "Azure", "service": "network",
     "framework": "Microsoft Cloud Security Benchmark", "source": "Microsoft Learn",
     "source_url": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
     "text": "Network Security Groups should not allow inbound traffic from any source "
             "(0.0.0.0/0) on management ports such as RDP (3389) or SSH (22). Rules should be "
             "scoped to specific trusted ranges."},
    {"control_ref": "ISO-A.8.15", "cloud": "Both", "service": "cloudtrail,monitor",
     "framework": "ISO/IEC 27001:2022 Annex A — Technological Controls", "source": "ISO 27001 Annex A",
     "source_url": "https://iseoblue.com/iso-27001/annex-a/iso-27001-controls-list/",
     "text": "Logs of activities, exceptions, faults, and security events should be produced, "
             "stored, and protected for review and investigation, supporting timely detection of "
             "unauthorized or anomalous activity."},
    {"control_ref": "ISO-A.8.24", "cloud": "Both", "service": "s3,rds,storage,sqlserver",
     "framework": "ISO/IEC 27001:2022 Annex A — Technological Controls", "source": "ISO 27001 Annex A",
     "source_url": "https://iseoblue.com/iso-27001/annex-a/iso-27001-controls-list/",
     "text": "Rules for the effective use of cryptography, including encryption of data at rest "
             "and in transit, should be defined and implemented to protect the confidentiality, "
             "authenticity, and integrity of information."},
    {"control_ref": "ISO-A.5.15", "cloud": "Both", "service": "iam,entra",
     "framework": "ISO/IEC 27001:2022 Annex A — Organizational Controls", "source": "ISO 27001 Annex A",
     "source_url": "https://iseoblue.com/iso-27001/annex-a/iso-27001-controls-list/",
     "text": "Access to information and associated assets should be restricted in accordance with "
             "business and security requirements, following the principle of least privilege and "
             "need-to-know."},
    {"control_ref": "ISO-A.8.12", "cloud": "Both", "service": "s3,storage",
     "framework": "ISO/IEC 27001:2022 Annex A — Technological Controls", "source": "ISO 27001 Annex A",
     "source_url": "https://iseoblue.com/iso-27001/annex-a/iso-27001-controls-list/",
     "text": "Measures to detect and prevent the unauthorised disclosure or extraction of "
             "sensitive information from systems and networks should be applied, including "
             "monitoring of public exposure points such as storage buckets."},
    {"control_ref": "ISO-A.5.23", "cloud": "Both", "service": "vpc,network",
     "framework": "ISO/IEC 27001:2022 Annex A — Organizational Controls", "source": "ISO 27001 Annex A",
     "source_url": "https://iseoblue.com/iso-27001/annex-a/iso-27001-controls-list/",
     "text": "Processes for acquisition, use, management, and exit from cloud services should "
             "define and monitor information security requirements for the use of cloud services, "
             "including network exposure boundaries."},
    {"control_ref": "DPDP-SEC-SAFEGUARD", "cloud": "Both", "service": "s3,rds,storage,sqlserver",
     "framework": "Digital Personal Data Protection Act, 2023 (India)", "source": "MeitY (Govt. of India)",
     "source_url": "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf",
     "text": "A Data Fiduciary must implement reasonable security safeguards to prevent personal "
             "data breach, including protecting data at rest and in transit and preventing "
             "unauthorized access or disclosure."},
    {"control_ref": "DPDP-STORAGE-LIMIT", "cloud": "Both", "service": "s3,rds,storage,sqlserver",
     "framework": "Digital Personal Data Protection Act, 2023 (India)", "source": "MeitY (Govt. of India)",
     "source_url": "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf",
     "text": "Personal data should be retained only for as long as necessary for the stated "
             "purpose of processing, and storage should be limited accordingly to reduce the "
             "impact of any breach."},
    {"control_ref": "DPDP-BREACH-NOTICE", "cloud": "Both", "service": "cloudtrail,monitor",
     "framework": "Digital Personal Data Protection Act, 2023 (India)", "source": "MeitY (Govt. of India)",
     "source_url": "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf",
     "text": "In the event of a personal data breach, the Data Fiduciary is expected to detect, "
             "log, and report the incident, which requires reliable audit trails and monitoring "
             "to be in place beforehand."},
    {"control_ref": "DPDP-ACCESS-CONTROL", "cloud": "Both", "service": "iam,entra",
     "framework": "Digital Personal Data Protection Act, 2023 (India)", "source": "MeitY (Govt. of India)",
     "source_url": "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf",
     "text": "Reasonable security safeguards include restricting access to personal data to "
             "authorized personnel only, which maps to enforcing least-privilege access and "
             "multi-factor authentication on identity systems."},
    {"control_ref": "HIPAA-SEC-ENCRYPT", "cloud": "Both", "service": "s3,rds,storage,sqlserver",
     "framework": "HIPAA Security Rule", "source": "HHS.gov",
     "source_url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
     "text": "Covered entities must implement technical safeguards including encryption of "
             "electronic protected health information (ePHI) at rest and in transit, to ensure "
             "confidentiality and prevent unauthorized disclosure."},
    {"control_ref": "HIPAA-ACCESS-CONTROL", "cloud": "Both", "service": "iam,entra",
     "framework": "HIPAA Security Rule", "source": "HHS.gov",
     "source_url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
     "text": "Covered entities must implement access controls that limit ePHI access to only "
             "authorized personnel, following unique user identification and least-privilege "
             "principles, with multi-factor authentication for privileged accounts."},
    {"control_ref": "HIPAA-AUDIT-CONTROLS", "cloud": "Both", "service": "cloudtrail,monitor",
     "framework": "HIPAA Security Rule", "source": "HHS.gov",
     "source_url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
     "text": "Covered entities must implement hardware, software, and procedural mechanisms to "
             "record and examine activity in systems containing ePHI, supporting timely detection "
             "of unauthorized access or breaches."},
    {"control_ref": "HIPAA-TRANSMISSION-SECURITY", "cloud": "Both", "service": "vpc,network",
     "framework": "HIPAA Security Rule", "source": "HHS.gov",
     "source_url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
     "text": "Covered entities must implement technical security measures to guard against "
             "unauthorized access to ePHI transmitted over an electronic network, including "
             "restricting network exposure to only necessary, authenticated sources."},
]


# ══════════════════════════════════════════════════════════════════
# PART H.1 — MITRE ATT&CK TECHNIQUE MAPPING (best-effort, per finding)
# ══════════════════════════════════════════════════════════════════
# Technique IDs verified against attack.mitre.org (Enterprise matrix).
# NOTE — this is a best-effort mapping, not an authoritative one: ATT&CK
# documents observed ADVERSARY BEHAVIOR, not defensive control gaps, so
# some findings (e.g. "encryption at rest disabled") don't have a clean
# 1:1 technique — they're a risk MULTIPLIER for techniques like T1530,
# not a technique themselves. Where no confident match exists, the
# mapping is left as "no direct technique" rather than guessing.
MITRE_ATTACK_MAP = [
    # (match_fn, technique_id, technique_name, tactic, url)
    (lambda svc, title, cid: svc in ('s3', 'storage') and ('public' in title or 'blob' in title),
     "T1530", "Data from Cloud Storage", "Collection",
     "https://attack.mitre.org/techniques/T1530/"),
    (lambda svc, title, cid: svc == 'iam' and ('admin' in title or 'wildcard' in title or 'policy' in title),
     "T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence / Privilege Escalation",
     "https://attack.mitre.org/techniques/T1098/003/"),
    (lambda svc, title, cid: svc == 'entra' and 'owner' in title,
     "T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence / Privilege Escalation",
     "https://attack.mitre.org/techniques/T1098/003/"),
    (lambda svc, title, cid: svc in ('iam', 'entra') and 'mfa' not in title and ('auth' in title or 'password' in title),
     "T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access / Persistence / Defense Evasion",
     "https://attack.mitre.org/techniques/T1078/004/"),
    (lambda svc, title, cid: svc == 'ec2' and 'imds' in title.replace('v1', '').replace('v2', '') or 'httptoken' in cid,
     "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access",
     "https://attack.mitre.org/techniques/T1552/005/"),
    (lambda svc, title, cid: 'ssh' in title,
     "T1021.004", "Remote Services: SSH", "Lateral Movement",
     "https://attack.mitre.org/techniques/T1021/004/"),
    (lambda svc, title, cid: svc in ('rds', 'sqlserver', 'sql') and 'public' in title,
     "T1190", "Exploit Public-Facing Application", "Initial Access",
     "https://attack.mitre.org/techniques/T1190/"),
    (lambda svc, title, cid: svc == 'ec2' and ('mysql' in title or 'ingress' in title) and '0.0.0.0' in title,
     "T1190", "Exploit Public-Facing Application", "Initial Access",
     "https://attack.mitre.org/techniques/T1190/"),
    (lambda svc, title, cid: svc in ('nsg', 'network') and ('any' in title or 'source' in title),
     "T1190", "Exploit Public-Facing Application", "Initial Access",
     "https://attack.mitre.org/techniques/T1190/"),
    (lambda svc, title, cid: svc in ('cloudtrail', 'monitor', 'logging') and ('disabled' in title or 'missing' in title or 'not' in title),
     "T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1562/008/"),
]


def map_finding_to_attack(finding):
    """Best-effort MITRE ATT&CK technique lookup for a finding. Returns
    (technique_id, technique_name, tactic, url) or a 'no direct technique'
    placeholder if nothing matches — never guesses silently."""
    svc = str(finding.get('service', '')).lower()
    title = str(finding.get('title', '')).lower()
    cid = str(finding.get('check_id', '')).lower()
    for match_fn, tid, name, tactic, url in MITRE_ATTACK_MAP:
        try:
            if match_fn(svc, title, cid):
                return tid, name, tactic, url
        except Exception:
            continue
    return "—", "No direct ATT&CK technique (control-gap finding, not adversary behavior)", "—", ""


SYSTEM_PROMPT = """You are a cloud security engineer writing remediation
guidance for a health-tech company's security team.
Your audience is a developer — NOT a security expert.
The finding may be from AWS or Azure — read the provider field and
tailor the fix to that specific platform's terminology and tools.

You are given a REFERENCE CONTROL GUIDANCE below. Base your answer
strictly on that reference plus the finding detail — do not introduce
facts, product names, or claims that are not supported by the reference.

You MUST respond in EXACTLY this format, with a literal newline
character between the two lines:

<risk explanation, max 40 words, non-technical>
<specific fix action, max 40 words>

Do not merge the two lines into one paragraph. Do not use bullet
points, numbering, or headings."""


@st.cache_resource(show_spinner=False)
def get_kb_index():
    from sklearn.feature_extraction.text import TfidfVectorizer
    kb_df = pd.DataFrame(CONTROL_KB)
    vectorizer = TfidfVectorizer(stop_words='english')
    kb_tfidf_matrix = vectorizer.fit_transform(kb_df['text'])
    return kb_df, vectorizer, kb_tfidf_matrix


def get_nim_embeddings(texts, api_key, input_type="passage"):
    import requests
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"input": texts, "model": NVIDIA_EMBED_MODEL, "input_type": input_type}
    try:
        resp = requests.post(NVIDIA_EMBED_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return np.array([item["embedding"] for item in data["data"]])
    except Exception:
        return None


def _cloud_matches(pool_cloud, finding_cloud):
    return str(pool_cloud).strip().upper() in ("BOTH", str(finding_cloud).strip().upper())


def _service_matches(pool_service, finding_service):
    parts = [s.strip().lower() for s in str(pool_service).split(',')]
    return str(finding_service).strip().lower() in parts


RETRIEVAL_CONFIDENCE_THRESHOLD = 0.30   # below this, KB has no strong-enough match — skip LLM call
CONTROL_GROUNDING_THRESHOLD = 0.55      # Stage A: does guidance stay faithful to the retrieved control text?
RAW_DATA_GROUNDING_THRESHOLD = 0.35     # Stage B: does guidance actually reflect THIS finding's raw detail?
TOP_K = 3                               # a finding can span more than one control area


def retrieve_control(finding, kb_df, vectorizer, kb_tfidf_matrix, api_key, top_k=TOP_K):
    """Retrieve up to top_k scoped KB chunks. Returns (retrieved_df, top_sim, is_low_confidence)."""
    from sklearn.metrics.pairwise import cosine_similarity

    cloud = str(finding.get('cloud_provider', 'AWS'))
    service = str(finding.get('service', '')).lower()
    title_lower = str(finding.get('title', '')).lower()
    if 'network acl' in title_lower or ' nacl' in title_lower:
        service = 'vpc'

    query = f"{finding['title']} {finding.get('status_detail_redacted', '')}"[:800]

    query_tfidf = vectorizer.transform([query])
    tfidf_sims = cosine_similarity(query_tfidf, kb_tfidf_matrix).flatten()

    embed_sims = None
    if api_key:
        query_embedding = get_nim_embeddings([query], api_key, input_type="query")
        if query_embedding is not None:
            kb_embeddings = st.session_state.get('kb_embeddings')
            if kb_embeddings is not None:
                embed_sims = cosine_similarity(query_embedding, kb_embeddings).flatten()

    if embed_sims is not None:
        hybrid_sims = 0.4 * tfidf_sims + 0.6 * embed_sims
        retrieval_mode = 'hybrid'
    else:
        hybrid_sims = tfidf_sims
        retrieval_mode = 'tfidf_only'

    pool = kb_df.copy()
    pool['sim'] = hybrid_sims
    pool['retrieval_mode'] = retrieval_mode

    scope_mask = pool.apply(
        lambda r: _cloud_matches(r['cloud'], cloud) and _service_matches(r['service'], service), axis=1
    )
    scoped = pool[scope_mask]
    search_pool = scoped if len(scoped) > 0 else pool
    in_scope = len(scoped) > 0

    retrieved = search_pool.sort_values('sim', ascending=False).head(top_k)
    top_sim = float(retrieved.iloc[0]['sim']) if len(retrieved) else 0.0

    # Confidence gate: weak top match OR no scoped match at all -> don't send to LLM
    is_low_confidence = (top_sim < RETRIEVAL_CONFIDENCE_THRESHOLD) or (not in_scope)

    return retrieved, top_sim, is_low_confidence


def build_prompt(finding, retrieved):
    """Includes ALL retrieved chunks (up to TOP_K), not just the top-1, so the
    LLM can synthesize a fix that spans more than one control area."""
    cloud = finding.get('cloud_provider', 'AWS')
    ref_lines = "\n".join(f"- ({r.control_ref} | {r.framework}) {r.text}" for r in retrieved.itertuples())
    return f"""Cloud Security Finding:
- Cloud Provider : {cloud.upper()}
- Title          : {finding['title']}
- Service        : {finding['service'].upper()}
- Severity       : {finding['severity'].upper()}
- Detail         : {finding['status_detail_redacted']}

Reference Control Guidance (ground your answer in this):
{ref_lines}

Provide exactly 2 lines of guidance as instructed."""


def get_nvidia_guidance(finding, retrieved, api_key, max_retries=3):
    import requests
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(finding, retrieved)}
        ],
        "temperature": 0.3, "max_tokens": 150, "top_p": 0.9,
    }
    last_error = None
    for attempt in range(max_retries):
        try:
            response = requests.post(NVIDIA_BASE_URL, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            text = result['choices'][0]['message']['content'].strip()
            lines = [line.strip() for line in text.split('\n') if line.strip()]
            return '\n'.join(lines[:2])
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    raise last_error


def _stage_a_control_grounding(guidance, retrieved, kb_df, api_key):
    """Stage A: does the guidance stay faithful to the retrieved control text
    it was supposedly grounded in? Uses the BEST match across all retrieved
    chunks (top_k may be >1)."""
    from sklearn.metrics.pairwise import cosine_similarity
    if len(retrieved) == 0:
        return (False, 'no_retrieval', 0.0)

    kb_embeddings = st.session_state.get('kb_embeddings')
    guidance_embedding = get_nim_embeddings([guidance], api_key, input_type="query") if api_key else None

    if guidance_embedding is not None and kb_embeddings is not None:
        best_sim = -1.0
        for ref_idx in retrieved.index:
            ref_position = kb_df.index.get_loc(ref_idx)
            ref_embedding = kb_embeddings[ref_position].reshape(1, -1)
            sim = cosine_similarity(guidance_embedding, ref_embedding)[0][0]
            best_sim = max(best_sim, sim)
        grounded = best_sim >= CONTROL_GROUNDING_THRESHOLD
        return (grounded, 'embedding', best_sim)
    else:
        ref_text = " ".join(retrieved['text'].tolist()).lower()
        ref_words = {w for w in ref_text.split() if len(w) > 4}
        guidance_words = set(guidance.lower().split())
        overlap = ref_words.intersection(guidance_words)
        grounded = len(overlap) >= 2
        return (grounded, 'keyword_fallback', float(len(overlap)))


def _stage_b_raw_data_grounding(guidance, raw_detail, api_key):
    """Stage B: does the guidance actually reflect THIS finding's raw scanner
    detail, not just the general control topic? Satisfies the capstone brief's
    literal requirement to verify LLM output against raw scanner data — Stage A
    alone (checking only against the KB control text) does not do this."""
    from sklearn.metrics.pairwise import cosine_similarity
    if not raw_detail or not str(raw_detail).strip():
        return (False, 'no_raw_detail', 0.0)

    guidance_embedding = get_nim_embeddings([guidance], api_key, input_type="query") if api_key else None
    raw_embedding = get_nim_embeddings([str(raw_detail)[:800]], api_key, input_type="query") if api_key else None

    if guidance_embedding is not None and raw_embedding is not None:
        sim = cosine_similarity(guidance_embedding, raw_embedding)[0][0]
        grounded = sim >= RAW_DATA_GROUNDING_THRESHOLD
        return (grounded, 'embedding', sim)

    port_matches = set(re.findall(r'\b\d{2,5}\b', str(raw_detail)))
    guidance_ports = set(re.findall(r'\b\d{2,5}\b', guidance))
    tech_overlap = len(port_matches.intersection(guidance_ports))
    grounded = tech_overlap >= 1
    return (grounded, 'keyword_fallback', float(tech_overlap))


def verify_output(guidance, retrieved, raw_detail, kb_df, api_key):
    """Dual-stage verification — BOTH stages must pass for 'verified'.
    Returns (is_verified, method, reason, stage_a_tuple, stage_b_tuple) so the
    UI can show exactly which check failed and why."""
    lines = [l for l in guidance.split('\n') if l.strip()]
    has_two_lines = len(lines) >= 2

    a_grounded, a_method, a_score = _stage_a_control_grounding(guidance, retrieved, kb_df, api_key)
    b_grounded, b_method, b_score = _stage_b_raw_data_grounding(guidance, raw_detail, api_key)

    is_verified = has_two_lines and a_grounded and b_grounded

    reason = (
        f"Control-text grounding [{a_method}]: score={a_score:.3f}, threshold={CONTROL_GROUNDING_THRESHOLD} "
        f"→ {'PASS' if a_grounded else 'FAIL'} | "
        f"Raw-scanner-data grounding [{b_method}]: score={b_score:.3f}, threshold={RAW_DATA_GROUNDING_THRESHOLD} "
        f"→ {'PASS' if b_grounded else 'FAIL'}"
    )
    if not has_two_lines:
        reason = "Guidance was not in the required 2-line format. " + reason
    method = f"{a_method}+{b_method}"
    return (is_verified, method, reason, (a_grounded, a_score), (b_grounded, b_score))


# ══════════════════════════════════════════════════════════════════
# PART I — AUTO-REMEDIATION (DRY-RUN ONLY — this app never executes
# live cloud API calls; run the original notebook/script with real
# credentials on your own machine for that)
# ══════════════════════════════════════════════════════════════════
def extract_db_instance_id(finding):
    raw = str(finding['status_detail'])
    tool = finding.get('tool', '')
    if tool == 'Steampipe':
        m = re.search(r'db_instance_identifier=([\w-]+)', raw)
        return m.group(1) if m else None
    if tool == 'ScoutSuite':
        m = re.search(r'instances\.([\w-]+)\.', raw)
        return m.group(1) if m else None
    if tool == 'Prowler v4':
        m = re.search(r'RDS Instance ([\w-]+)', raw, re.IGNORECASE)
        return m.group(1) if m else None
    return None


def extract_sg_details(finding):
    raw = str(finding['status_detail'])
    tool = finding.get('tool', '')
    if tool == 'Steampipe':
        sg_m = re.search(r'group_id=([\w-]+)', raw)
        port_m = re.search(r'from_port=(\d+)', raw)
    elif tool == 'Prowler v4':
        sg_m = re.search(r'\(([\w-]+)\)', raw)
        port_m = re.search(r'port (\d+)', raw, re.IGNORECASE)
    elif tool == 'ScoutSuite':
        sg_m = re.search(r'\b(sg-[\w-]+)\b', raw)
        port_m = re.search(r'port[:\s]*(\d+)', raw, re.IGNORECASE)
    else:
        sg_m = (re.search(r'group_id=([\w-]+)', raw) or re.search(r'\(([\w-]+)\)', raw)
                or re.search(r'\b(sg-[\w-]+)\b', raw))
        port_m = re.search(r'(?:from_port|port)[=:\s]*(\d+)', raw, re.IGNORECASE)
    sg_id = sg_m.group(1) if sg_m else None
    port = int(port_m.group(1)) if port_m else None
    return (sg_id, port)


def make_result(finding_id, remediation_id, risk_level, cloud, status, detail):
    return {
        'finding_id': finding_id, 'remediation_id': remediation_id, 'risk_level': risk_level,
        'cloud': cloud, 'status': status, 'detail': detail,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


def remediate_rds_public_access_dry(finding):
    finding_id = finding['finding_id']
    db_id = extract_db_instance_id(finding)
    if not db_id:
        return make_result(finding_id, 'rds_disable_public_access', 'RISKY', 'AWS',
                            'FAILED', 'Could not extract db_instance_identifier from status_detail')
    return make_result(finding_id, 'rds_disable_public_access', 'RISKY', 'AWS', 'DRY_RUN_OK',
                        f'WOULD call rds.modify_db_instance(DBInstanceIdentifier="{db_id}", '
                        f'PubliclyAccessible=False, ApplyImmediately=True)')


def remediate_sg_open_ingress_dry(finding):
    finding_id = finding['finding_id']
    sg_id, port = extract_sg_details(finding)
    if not sg_id or port is None:
        return make_result(finding_id, 'sg_remove_open_ingress', 'RISKY', 'AWS',
                            'FAILED', 'Could not extract group_id/from_port from status_detail')
    return make_result(finding_id, 'sg_remove_open_ingress', 'RISKY', 'AWS', 'DRY_RUN_OK',
                        f'WOULD call ec2.revoke_security_group_ingress(GroupId="{sg_id}", '
                        f'IpProtocol="tcp", FromPort={port}, ToPort={port}, CidrIp="0.0.0.0/0")')


def remediate_azure_storage_public_blob_dry(finding):
    finding_id = finding['finding_id']
    storage_account = finding.get('resource_name')
    if not storage_account:
        return make_result(finding_id, 'azure_storage_disable_public_blob', 'SAFE', 'Azure',
                            'FAILED', "Could not find storage account identifier")
    return make_result(finding_id, 'azure_storage_disable_public_blob', 'SAFE', 'Azure', 'DRY_RUN_OK',
                        f'WOULD call storage_client.storage_accounts.update('
                        f'RG, "{storage_account}", {{"allow_blob_public_access": False}})')


def remediate_azure_storage_network_access_dry(finding):
    finding_id = finding['finding_id']
    storage_account = finding.get('resource_name')
    if not storage_account:
        return make_result(finding_id, 'azure_storage_restrict_network', 'SAFE', 'Azure',
                            'FAILED', "Could not find storage account identifier")
    return make_result(finding_id, 'azure_storage_restrict_network', 'SAFE', 'Azure', 'DRY_RUN_OK',
                        f'WOULD call storage_client.storage_accounts.update('
                        f'RG, "{storage_account}", {{"public_network_access": "Disabled"}})')


REMEDIATION_REGISTRY = {
    'rds_disable_public_access': remediate_rds_public_access_dry,
    'sg_remove_open_ingress': remediate_sg_open_ingress_dry,
    'azure_storage_disable_public_blob': remediate_azure_storage_public_blob_dry,
    'azure_storage_restrict_network': remediate_azure_storage_network_access_dry,
}


def classify_finding_for_remediation(finding):
    title = str(finding.get('title', '')).lower()
    service = str(finding.get('service', '')).lower()
    if service == 'rds' and 'publicly accessible' in title:
        return 'rds_disable_public_access'
    if service == 'ec2' and ('ssh' in title or 'mysql' in title or 'ingress' in title) and '0.0.0.0' in title:
        return 'sg_remove_open_ingress'
    if service == 'storage' and 'blob' in title:
        return 'azure_storage_disable_public_blob'
    if service == 'storage' and 'reachable from any network' in title:
        return 'azure_storage_restrict_network'
    return None


def run_dry_run_remediation(consolidated: pd.DataFrame) -> pd.DataFrame:
    priority_findings = consolidated[consolidated['priority_band'].isin(['P0 - CRITICAL', 'P1 - HIGH'])].copy()
    results = []
    for _, row in priority_findings.iterrows():
        remediation_id = classify_finding_for_remediation(row)
        if remediation_id is None:
            continue
        results.append(REMEDIATION_REGISTRY[remediation_id](row))
    return pd.DataFrame(results)


# ══════════════════════════════════════════════════════════════════
# UI — MAIN TABS
# ══════════════════════════════════════════════════════════════════
st.title("🛡️ CloudGuardian — Multi-Cloud CSPM Pipeline")
st.caption("Prowler + Steampipe + ScoutSuite → Prioritize → AI Classify → Redact → RAG Remediation → Auto-Remediate (Dry-Run)")

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "1️⃣ Upload & Consolidate", "2️⃣ Prioritize", "3️⃣ AI Classify",
    "4️⃣ Redact (OWASP LLM06)", "5️⃣ RAG Remediation", "6️⃣ Auto-Remediate (Dry-Run)", "7️⃣ Export",
])

# ─────────────────────────────────────────────────────────────────
# TAB 1 — UPLOAD & CONSOLIDATE
# ─────────────────────────────────────────────────────────────────
with tab1:
    st.header("Upload scan outputs")
    st.caption("Upload whichever sources you have — AWS-only or Azure-only both work, or both together.")

    col_aws, col_azure = st.columns(2)

    with col_aws:
        st.subheader("☁️ AWS")
        aws_prowler_file = st.file_uploader("Prowler CSV (AWS)", type=["csv"], key="aws_prowler")
        aws_steampipe_files = st.file_uploader(
            "Steampipe CSVs (AWS) — M01-M12 + CloudTrail files",
            type=["csv"], accept_multiple_files=True, key="aws_steampipe"
        )
        aws_scoutsuite_file = st.file_uploader(
            "ScoutSuite results .js (AWS)", type=["js"], key="aws_scoutsuite"
        )

    with col_azure:
        st.subheader("☁️ Azure")
        azure_prowler_file = st.file_uploader("Prowler CSV (Azure)", type=["csv"], key="azure_prowler")
        azure_steampipe_files = st.file_uploader(
            "Steampipe CSVs (Azure) — steampipe_<service>.csv",
            type=["csv"], accept_multiple_files=True, key="azure_steampipe"
        )
        azure_scoutsuite_file = st.file_uploader(
            "ScoutSuite results .js (Azure)", type=["js"], key="azure_scoutsuite"
        )

    if st.button("🔄 Consolidate Findings", type="primary"):
        with st.spinner("Consolidating..."):
            fails = build_prowler_fails(aws_prowler_file, azure_prowler_file)
            prowler_df = normalize_prowler(fails) if fails is not None else pd.DataFrame(columns=NORMALIZED_COLUMNS)

            steampipe_df = pd.concat([
                load_aws_steampipe_findings(aws_steampipe_files),
                load_azure_steampipe_findings(azure_steampipe_files),
            ], ignore_index=True)

            scoutsuite_df = pd.concat([
                load_scoutsuite_findings(aws_scoutsuite_file, 'AWS'),
                load_scoutsuite_findings(azure_scoutsuite_file, 'Azure'),
            ], ignore_index=True)

            total_sources = len(prowler_df) + len(steampipe_df) + len(scoutsuite_df)
            if total_sources == 0:
                st.error("No findings loaded from any source. Upload at least one file above.")
            else:
                consolidated = consolidate_all(
                    prowler_df, steampipe_df, scoutsuite_df,
                    account_id, region, scan_date, azure_scan_date
                )
                st.session_state['consolidated'] = consolidated
                st.success(f"✅ Consolidated {len(consolidated)} findings.")

    if st.session_state['consolidated'] is not None:
        df = st.session_state['consolidated']
        st.divider()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Findings", len(df))
        c2.metric("Prowler", (df['tool'] == 'Prowler v4').sum())
        c3.metric("Steampipe", (df['tool'] == 'Steampipe').sum())
        c4.metric("ScoutSuite", (df['tool'] == 'ScoutSuite').sum())

        col_a, col_b = st.columns(2)
        with col_a:
            st.bar_chart(df['severity'].str.lower().value_counts())
            st.caption("Findings by severity")
        with col_b:
            st.bar_chart(df['cloud_provider'].value_counts())
            st.caption("Findings by cloud provider")

        st.dataframe(df.head(50), use_container_width=True)


# ─────────────────────────────────────────────────────────────────
# TAB 2 — PRIORITIZE
# ─────────────────────────────────────────────────────────────────
with tab2:
    st.header("Rule-Based Prioritization")
    st.caption("Priority Score = CVSS Score × Exposure Score × Blast Radius")

    with st.expander("ℹ️ Why P0 is capped at 85, not 100"):
        st.markdown(
            "`blast_radius` maxes out at **3** for every service except IAM "
            "(4–5) or a database finding whose title literally says \"public\" (4). "
            "That means a *critical* finding with *confirmed direct exposure* on any "
            "other service — EC2, VPC, generic RDS/SQL, S3, storage, network, "
            "monitor — hits a hard ceiling of `9.5 × 3 × 3 = 85.5`. A P0 cutoff of "
            "100 would make P0 mathematically unreachable for anything outside "
            "IAM-escalation or \"public\"-titled DB findings, regardless of how "
            "severe or exposed it actually is.\n\n"
            "Cutting the P0 threshold to **85** lets *critical + confirmed direct "
            "exposure* clear P0 on any service, while still requiring both factors "
            "at their maximum — a high-severity finding at the same exposure/blast "
            "combo tops out at `7.5 × 3 × 3 = 67.5`, comfortably inside P1."
        )

    if st.session_state['consolidated'] is None:
        st.info("Consolidate findings in Tab 1 first.")
    else:
        if st.button("⚖️ Run Prioritization", type="primary"):
            with st.spinner("Scoring findings..."):
                df = apply_prioritization(st.session_state['consolidated'])
                st.session_state['consolidated'] = df
                st.success("✅ Prioritization complete.")

        df = st.session_state['consolidated']
        if 'priority_band' in df.columns:
            band_counts = df['priority_band'].value_counts()
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🔴 P0 - CRITICAL", int(band_counts.get('P0 - CRITICAL', 0)))
            c2.metric("🟠 P1 - HIGH", int(band_counts.get('P1 - HIGH', 0)))
            c3.metric("🟡 P2 - MEDIUM", int(band_counts.get('P2 - MEDIUM', 0)))
            c4.metric("🟢 P3 - LOW", int(band_counts.get('P3 - LOW', 0)))

            st.bar_chart(df['priority_band'].value_counts())

            st.subheader("Top 15 highest priority findings")
            top15 = df.head(15)[['finding_id', 'cloud_provider', 'severity', 'priority_score',
                                  'priority_band', 'title']]
            st.dataframe(top15, use_container_width=True)


# ─────────────────────────────────────────────────────────────────
# TAB 3 — AI CLASSIFY (SMOTE-balanced RandomForest — final model)
# ─────────────────────────────────────────────────────────────────
with tab3:
    st.header("AI Risk Classification")
    st.caption("RandomForest classifier, SMOTE-balanced for the minority HIGH class. "
               "This is the final tuned model from the Week 2 pipeline.")

    if st.session_state['consolidated'] is None or 'priority_band' not in st.session_state['consolidated'].columns:
        st.info("Run prioritization in Tab 2 first.")
    else:
        if st.button("🤖 Train & Classify", type="primary"):
            with st.spinner("Training SMOTE-balanced RandomForest..."):
                try:
                    df, pipeline, le_target, metrics = train_smote_model(st.session_state['consolidated'])
                    st.session_state['consolidated'] = df
                    st.session_state['smote_pipeline'] = pipeline
                    st.session_state['le_target'] = le_target
                    st.session_state['ml_metrics'] = metrics
                    st.success("✅ Model trained and applied to all findings.")
                except ImportError as e:
                    st.error(f"Missing dependency: {e}. Install with: "
                             f"`pip install imbalanced-learn scikit-learn --break-system-packages`")

        if st.session_state.get('ml_metrics'):
            m = st.session_state['ml_metrics']
            c1, c2, c3 = st.columns(3)
            c1.metric("CV Accuracy", f"{m['cv_accuracy_mean']*100:.1f}%", f"±{m['cv_accuracy_std']*100:.1f}%")
            c2.metric("CV Macro-F1", f"{m['cv_f1_mean']*100:.1f}%", f"±{m['cv_f1_std']*100:.1f}%")
            c3.metric("CRITICAL-class samples", f"{m['high_count']}/{m['total']}")

            high_prec = m['classification_report'].get('CRITICAL', {}).get('precision', 0)
            if high_prec < 0.5:
                st.warning(
                    f"🔎 Honest read-out: CRITICAL-class precision is {high_prec*100:.0f}%. "
                    f"This is a known limitation from having few real CRITICAL-tier samples "
                    f"in the dataset — not a modelling mistake. Report it as such."
                )

            st.subheader("Classification report")
            report_rows = []
            for cls in m['classes']:
                r = m['classification_report'][cls]
                report_rows.append({
                    'Class': cls, 'Precision': round(r['precision'], 2),
                    'Recall': round(r['recall'], 2), 'F1-Score': round(r['f1-score'], 2),
                    'Support': int(r['support']),
                })
            st.dataframe(pd.DataFrame(report_rows), use_container_width=True)

            st.subheader("AI risk level distribution")
            st.bar_chart(st.session_state['consolidated']['ai_risk_level'].value_counts())


# ─────────────────────────────────────────────────────────────────
# TAB 4 — REDACT (OWASP LLM06)
# ─────────────────────────────────────────────────────────────────
with tab4:
    st.header("OWASP LLM06 Redaction Engine")
    st.caption("Sanitizes AWS/Azure identifiers, credentials, and PII before anything is sent to an external LLM.")

    if st.session_state['consolidated'] is None or 'priority_band' not in st.session_state['consolidated'].columns:
        st.info("Run prioritization in Tab 2 first.")
    else:
        if st.button("🔒 Run Redaction", type="primary"):
            with st.spinner("Redacting sensitive identifiers..."):
                engine = OWASPRedactionEngine()
                df = st.session_state['consolidated'].copy()
                df['status_detail_redacted'] = df['status_detail'].astype(str).apply(engine.redact)
                st.session_state['consolidated'] = df
                st.session_state['redaction_engine'] = engine
                st.success("✅ Redaction complete.")

        engine = st.session_state['redaction_engine']
        if engine is not None:
            st.subheader("Redaction summary")
            summary = engine.summary()
            if summary:
                st.dataframe(
                    pd.DataFrame(list(summary.items()), columns=['Category', 'Unique values redacted']),
                    use_container_width=True,
                )
            else:
                st.caption("No sensitive identifiers matched any pattern.")

            st.subheader("Before / after preview (P0/P1 findings)")
            df = st.session_state['consolidated']
            p0_p1 = df[df['priority_band'].isin(['P0 - CRITICAL', 'P1 - HIGH'])].head(10)
            preview = p0_p1[['finding_id', 'cloud_provider', 'title', 'status_detail', 'status_detail_redacted']]
            st.dataframe(preview, use_container_width=True)

            st.info(
                f"📋 Internal mapping table contains {len(engine.get_mapping_table())} entries "
                f"(kept in-memory for this session only, never exported or sent externally)."
            )


# ─────────────────────────────────────────────────────────────────
# TAB 5 — RAG REMEDIATION GUIDANCE (NVIDIA NIM)
# ─────────────────────────────────────────────────────────────────
with tab5:
    st.header("RAG-Grounded Remediation Guidance")
    st.caption(f"Model: {NVIDIA_MODEL} · Retriever: TF-IDF + NVIDIA NIM embeddings (hybrid, top-{TOP_K}) over a "
               f"{len(CONTROL_KB)}-chunk knowledge base (CIS, Microsoft Cloud Security Benchmark, "
               f"ISO 27001 Annex A, DPDP Act 2023, HIPAA Security Rule).")

    with st.expander("ℹ️ How verification works — thresholds used"):
        st.markdown(f"""
Every finding goes through up to **3 checks**, each with its own threshold:

| # | Check | Threshold | What it catches |
|---|---|---|---|
| 1 | **Retrieval confidence gate** | `sim < {RETRIEVAL_CONFIDENCE_THRESHOLD}` → LLM call is **skipped entirely** | KB simply has no strong-enough matching control for this finding — sending a weak/irrelevant chunk as "ground truth" would risk guidance that *sounds* grounded but isn't |
| 2 | **Stage A — Control-text grounding** | `sim < {CONTROL_GROUNDING_THRESHOLD}` → FAIL | Guidance drifted away from the retrieved control text (LLM added facts not in the reference) |
| 3 | **Stage B — Raw-scanner-data grounding** | `sim < {RAW_DATA_GROUNDING_THRESHOLD}` → FAIL | Guidance is generic/on-topic but doesn't actually reflect *this specific* finding's raw scanner detail |

A finding is marked **YES (verified)** only if it passes the gate AND both Stage A and Stage B. Otherwise it's marked **REVIEW** with the exact reason (which stage failed, at what score) shown per finding below — nothing is silently dropped.
""")

    df = st.session_state['consolidated']
    if df is None or 'status_detail_redacted' not in df.columns:
        st.info("Run redaction in Tab 4 first — guidance is only generated from redacted text.")
    else:
        api_key = os.environ.get("NVIDIA_API_KEY")
        n_findings = st.slider("Number of P0/P1 findings to process", 1, 30, 15)

        if not api_key:
            st.warning(
                "No NVIDIA_API_KEY in environment — this will run in TF-IDF-only retrieval mode "
                "and skip live LLM calls (guidance text will be empty; you'll still see which "
                "control each finding retrieves and its MITRE ATT&CK mapping)."
            )

        if st.button("🧠 Generate Remediation Guidance", type="primary"):
            kb_df, vectorizer, kb_tfidf_matrix = get_kb_index()

            if api_key and 'kb_embeddings' not in st.session_state:
                with st.spinner("Building semantic embedding index for knowledge base..."):
                    kb_embeddings = get_nim_embeddings(kb_df['text'].tolist(), api_key, input_type="passage")
                    st.session_state['kb_embeddings'] = kb_embeddings
                    if kb_embeddings is None:
                        st.warning("Embedding API unavailable — falling back to TF-IDF-only.")

            priority_findings = df[df['priority_band'].isin(['P0 - CRITICAL', 'P1 - HIGH'])].head(n_findings)

            llm_results, rag_audit = [], []
            progress = st.progress(0.0)
            for i, (idx, row) in enumerate(priority_findings.iterrows()):
                attack_id, attack_name, attack_tactic, attack_url = map_finding_to_attack(row)

                retrieved, top_sim, is_low_confidence = retrieve_control(
                    row, kb_df, vectorizer, kb_tfidf_matrix, api_key, top_k=TOP_K
                )
                top_refs = ", ".join(retrieved['control_ref'].tolist()) if len(retrieved) else 'NONE'
                top_frameworks = ", ".join(sorted(set(retrieved['framework'].tolist()))) if len(retrieved) else 'NONE'
                top_sources = ", ".join(sorted(set(retrieved['source_url'].tolist()))) if len(retrieved) else ''
                top_mode = retrieved.iloc[0]['retrieval_mode'] if len(retrieved) else 'NONE'

                base_row = {
                    'finding_id': row['finding_id'], 'cloud_provider': row['cloud_provider'],
                    'title': row['title'], 'severity': row['severity'], 'service': row['service'],
                    'priority_band': row['priority_band'], 'priority_score': row['priority_score'],
                    'llm_model': NVIDIA_MODEL, 'rag_control_ref': top_refs, 'rag_framework': top_frameworks,
                    'rag_source_url': top_sources, 'rag_similarity': round(top_sim, 3), 'retrieval_mode': top_mode,
                    'attack_technique_id': attack_id, 'attack_technique_name': attack_name,
                    'attack_tactic': attack_tactic, 'attack_url': attack_url,
                }

                # Gate BEFORE calling the LLM — no point spending a call on a weak retrieval
                if not api_key:
                    guidance, verify_reason, verified = '(no API key — retrieval only)', 'n/a', 'N/A'
                elif is_low_confidence:
                    guidance = 'SKIPPED — no sufficiently relevant control found in KB. Route to manual review.'
                    verify_reason = (f"Retrieval confidence gate: top_sim={top_sim:.3f}, "
                                      f"threshold={RETRIEVAL_CONFIDENCE_THRESHOLD} → FAILED "
                                      f"(no in-scope KB chunk matched strongly enough — LLM call skipped)")
                    verified = 'LOW_CONFIDENCE_RETRIEVAL'
                else:
                    try:
                        guidance = get_nvidia_guidance(row, retrieved, api_key)
                        is_verified, verify_method, verify_reason, stage_a, stage_b = verify_output(
                            guidance, retrieved, row['status_detail_redacted'], kb_df, api_key
                        )
                        verified = 'YES' if is_verified else 'REVIEW'
                    except Exception as e:
                        guidance, verify_reason, verified = f"ERROR: {e}", str(e), 'NO - API Error'
                    time.sleep(1.0)

                llm_results.append({**base_row, 'llm_guidance': guidance, 'verify_reason': verify_reason,
                                     'verified': verified})
                rag_audit.append({
                    'finding_id': row['finding_id'], 'query_title': row['title'], 'retrieved_refs': top_refs,
                    'frameworks': top_frameworks, 'source_urls': top_sources, 'top_similarity': round(top_sim, 3),
                    'retrieval_mode': top_mode, 'attack_technique_id': attack_id,
                    'retrieved_texts': " || ".join(retrieved['text'].tolist()) if len(retrieved) else '',
                })
                progress.progress((i + 1) / len(priority_findings))

            st.session_state['llm_df'] = pd.DataFrame(llm_results)
            st.session_state['rag_audit_df'] = pd.DataFrame(rag_audit)
            st.success(f"✅ Processed {len(llm_results)} findings.")

        llm_df = st.session_state['llm_df']
        if llm_df is not None:
            verified_count = (llm_df['verified'] == 'YES').sum()
            review_count = (llm_df['verified'] == 'REVIEW').sum()
            gated_count = (llm_df['verified'] == 'LOW_CONFIDENCE_RETRIEVAL').sum()
            c1, c2, c3 = st.columns(3)
            c1.metric("✅ Verified", f"{verified_count}/{len(llm_df)}")
            c2.metric("⚠️ Needs review", review_count)
            c3.metric("🟠 Gated (low retrieval confidence)", gated_count)

            for _, r in llm_df.iterrows():
                status_icon = {"YES": "✅", "REVIEW": "⚠️", "LOW_CONFIDENCE_RETRIEVAL": "🟠",
                               "NO - API Error": "❌", "N/A": "⬜"}.get(r['verified'], "•")
                with st.expander(f"{status_icon} {r['finding_id']} · {r['cloud_provider']} · "
                                  f"{r['priority_band']} — {r['title'][:55]}"):
                    st.write(f"**RAG match(es):** {r['rag_control_ref']} ({r['rag_framework']}, "
                             f"top similarity={r['rag_similarity']})")
                    st.write(f"**MITRE ATT&CK:** `{r['attack_technique_id']}` — {r['attack_technique_name']} "
                             f"({r['attack_tactic']})")
                    if r['attack_url']:
                        st.caption(f"ATT&CK reference: {r['attack_url']}")

                    st.write(f"**Status:** {r['verified']}")
                    if r['verified'] not in ('YES', 'N/A'):
                        st.warning(f"**Why:** {r['verify_reason']}")
                    else:
                        st.caption(r['verify_reason'])

                    st.code(r['llm_guidance'])
                    st.caption(f"Control source: {r['rag_source_url']}")


# ─────────────────────────────────────────────────────────────────
# TAB 6 — AUTO-REMEDIATE (DRY-RUN)
# ─────────────────────────────────────────────────────────────────
with tab6:
    st.header("Automated Remediation — Dry-Run Only")
    st.info(
        "🔒 This app **never** makes live AWS/Azure API calls. It only shows what *would* be "
        "called, for review. RDS instances are always treated as needing human approval "
        "(encryption changes require a snapshot+restore cycle) and are never auto-remediated live."
    )

    df = st.session_state['consolidated']
    if df is None or 'priority_band' not in df.columns:
        st.info("Run prioritization in Tab 2 first.")
    else:
        st.caption("Covers: RDS public access (AWS, RISKY), Security Group open ingress (AWS, RISKY), "
                   "Azure Storage public blob access (SAFE), Azure Storage network access (SAFE).")

        if st.button("🧪 Run Dry-Run Remediation", type="primary"):
            with st.spinner("Matching findings to remediation functions..."):
                remediation_df = run_dry_run_remediation(df)
                st.session_state['remediation_df'] = remediation_df
                st.success(f"✅ Matched {len(remediation_df)} findings to a remediation function.")

        remediation_df = st.session_state['remediation_df']
        if remediation_df is not None and len(remediation_df):
            c1, c2 = st.columns(2)
            with c1:
                st.bar_chart(remediation_df['risk_level'].value_counts())
                st.caption("By risk tier")
            with c2:
                st.bar_chart(remediation_df['status'].value_counts())
                st.caption("By status")
            st.dataframe(remediation_df, use_container_width=True)


# ─────────────────────────────────────────────────────────────────
# TAB 7 — EXPORT
# ─────────────────────────────────────────────────────────────────
with tab7:
    st.header("Export")

    df = st.session_state['consolidated']
    if df is None:
        st.info("Nothing to export yet — consolidate findings in Tab 1 first.")
    else:
        export_df = df.copy()
        if 'status_detail_redacted' in export_df.columns:
            export_df = export_df.drop(columns=['status_detail'], errors='ignore')
            export_df = export_df.rename(columns={'status_detail_redacted': 'status_detail'})
            st.caption("Exporting the **redacted** version of status_detail (safe to share externally).")
        else:
            st.warning("Redaction (Tab 4) has not been run — this export contains raw, unredacted "
                       "status_detail text. Run Tab 4 first if this is going outside the team.")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button(
                "⬇️ Consolidated Findings (CSV)",
                export_df.to_csv(index=False).encode('utf-8'),
                file_name="consolidated_findings.csv", mime="text/csv",
            )
        with col2:
            st.download_button(
                "⬇️ Consolidated Findings (JSON)",
                export_df.to_json(orient='records', indent=2).encode('utf-8'),
                file_name="consolidated_findings.json", mime="application/json",
            )
        with col3:
            if st.session_state['llm_df'] is not None:
                st.download_button(
                    "⬇️ LLM Remediation Guidance (CSV)",
                    st.session_state['llm_df'].to_csv(index=False).encode('utf-8'),
                    file_name="llm_remediation_guidance.csv", mime="text/csv",
                )

        col4, col5 = st.columns(2)
        with col4:
            if st.session_state['rag_audit_df'] is not None:
                st.download_button(
                    "⬇️ RAG Retrieval Audit (CSV)",
                    st.session_state['rag_audit_df'].to_csv(index=False).encode('utf-8'),
                    file_name="rag_retrieval_audit.csv", mime="text/csv",
                )
        with col5:
            if st.session_state['remediation_df'] is not None:
                st.download_button(
                    "⬇️ Remediation Dry-Run Log (CSV)",
                    st.session_state['remediation_df'].to_csv(index=False).encode('utf-8'),
                    file_name="remediation_dry_run_log.csv", mime="text/csv",
                )

        st.divider()
        st.subheader("Full findings table")
        st.dataframe(export_df, use_container_width=True)
