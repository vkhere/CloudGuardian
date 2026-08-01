"""
tools/generate_sample_reports.py
================================
Produces sample normalized reports in ../reports so the console runs out of
the box and tells a full Week 1 -> Week 3 story for BOTH clouds. It also
doubles as living documentation of the report schema: every column the
dashboard expects is written here.

Run:  python tools/generate_sample_reports.py
Then replace the generated CSVs with your real scan output (same columns).
"""

from __future__ import annotations

import csv
import os

FINDING_FIELDS = [
    "cloud", "week", "scan_stage", "scan_id", "captured_at",
    "finding_id", "account_id", "service", "resource_name", "region",
    "check_id", "title", "description", "severity", "status", "source_tool", "detected_by",
    "risk_score", "cvss", "exposure", "blast_radius", "remediation",
    "llm_confidence", "verification_status", "iso_27001", "cis_control",
    "mitre_attck", "is_catalogued_misconfig",
]


# Which scanners independently raised each finding. Pipe-separated so one CSV
# column can express multi-tool detection. This is what drives the cross-tool
# agreement page.
DETECTED_BY = {
    "AZ-STG-PUBLIC-CONTAINER": "Prowler|ScoutSuite|Steampipe",
    "AZ-NET-SSH-OPEN": "Prowler|ScoutSuite",
    "AZ-SQL-FW-ALLOWALL": "Prowler|Steampipe",
    "AZ-VM-PWD-AUTH": "ScoutSuite",
    "AZ-STG-PUBNET": "Prowler|Steampipe",
    "AZ-STG-LOG-OFF": "Steampipe",
    "AZ-KV-PUBLIC": "Prowler",
    "AZ-SQL-TDE": "ScoutSuite",
    "AZ-MON-ACTLOG-ALERT": "Steampipe|ScoutSuite",
    "AZ-IAM-MI-MISSING": "ScoutSuite",
    "AWS-S3-PUBLIC": "Prowler|ScoutSuite|Steampipe",
    "AWS-EC2-SSH-OPEN": "Prowler|ScoutSuite",
    "AWS-IAM-ADMIN": "ScoutSuite|Steampipe",
    "AWS-RDS-UNENCRYPTED": "Prowler|Steampipe",
    "AWS-CLOUDTRAIL-OFF": "Steampipe",
    "AWS-ROOT-KEYS": "Prowler|ScoutSuite|Steampipe",
}

# Each check is defined once; per-stage we only flip its status.
# key: finding_id -> attributes (everything except status)
AZURE = {
    "AZ-STG-PUBLIC-CONTAINER": dict(service="Storage", resource_name="stcloudguardianlab", region="Central US",
        check_id="storage_blob_public_access", title="Blob container is publicly readable",
        description="Anonymous public read access is allowed on a blob container.",
        severity="Critical", source_tool="Prowler", risk_score=95, cvss="9.1", exposure="Public",
        blast_radius="Subscription", remediation="Set container access to Private and disable anonymous blob access on the account.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.3 Access restriction",
        cis_control="CIS 3.7", mitre_attck="T1530", is_catalogued_misconfig="Yes"),
    "AZ-NET-SSH-OPEN": dict(service="Network", resource_name="nsg-web-cloudguardian", region="Central US",
        check_id="nsg_ssh_open_internet", title="SSH (22) open to the internet",
        description="An inbound NSG rule allows 0.0.0.0/0 on TCP 22.",
        severity="Critical", source_tool="Prowler", risk_score=93, cvss="8.6", exposure="Public",
        blast_radius="Resource", remediation="Restrict SSH to your /32 or use Azure Bastion instead of public SSH.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.20 Network security",
        cis_control="CIS 6.1", mitre_attck="T1110", is_catalogued_misconfig="Yes"),
    "AZ-SQL-FW-ALLOWALL": dict(service="SQL", resource_name="sql-cloudguardian-lab", region="Central US",
        check_id="sql_firewall_allow_all", title="SQL firewall allows all IPs",
        description="A firewall rule spans 0.0.0.0-255.255.255.255.",
        severity="Critical", source_tool="Prowler", risk_score=90, cvss="8.2", exposure="Public",
        blast_radius="Resource", remediation="Remove the allow-all rule; permit only required IPs or Azure services.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.20 Network security",
        cis_control="CIS 4.1", mitre_attck="T1190", is_catalogued_misconfig="Yes"),
    "AZ-VM-PWD-AUTH": dict(service="Compute", resource_name="vm-web-cloudguardian", region="Central US",
        check_id="vm_password_auth_enabled", title="VM allows SSH password auth",
        description="The Linux VM accepts password-based SSH login.",
        severity="High", source_tool="ScoutSuite", risk_score=72, cvss="7.0", exposure="Public",
        blast_radius="Resource", remediation="Disable password authentication; rely on SSH keys only.",
        llm_confidence="Medium", verification_status="Verified", iso_27001="A.8.5 Secure authentication",
        cis_control="CIS 6.2", mitre_attck="T1110", is_catalogued_misconfig="Yes"),
    "AZ-STG-PUBNET": dict(service="Storage", resource_name="stcloudguardianlab", region="Central US",
        check_id="storage_public_network_access", title="Storage reachable from all networks",
        description="Public network access is enabled on the storage account.",
        severity="High", source_tool="Prowler", risk_score=70, cvss="6.5", exposure="Public",
        blast_radius="Subscription", remediation="Disable public network access; use private endpoints or selected networks.",
        llm_confidence="Medium", verification_status="Verified", iso_27001="A.8.20 Network security",
        cis_control="CIS 3.8", mitre_attck="T1530", is_catalogued_misconfig="Yes"),
    "AZ-STG-LOG-OFF": dict(service="Logging", resource_name="stcloudguardianlab", region="Central US",
        check_id="storage_logging_disabled", title="Diagnostic logging disabled on storage",
        description="Storage access logs are not sent to Log Analytics.",
        severity="Medium", source_tool="Steampipe", risk_score=55, cvss="5.3", exposure="Internal",
        blast_radius="Subscription", remediation="Enable diagnostic settings and route logs to Log Analytics.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.15 Logging",
        cis_control="CIS 3.10", mitre_attck="T1562", is_catalogued_misconfig="Yes"),
    "AZ-KV-PUBLIC": dict(service="KeyVault", resource_name="kv-cloudguardian-lab", region="Central US",
        check_id="keyvault_public_access", title="Key Vault open to all networks",
        description="The Key Vault firewall is not restricting network access.",
        severity="High", source_tool="Prowler", risk_score=68, cvss="6.8", exposure="Public",
        blast_radius="Subscription", remediation="Enable the Key Vault firewall; allow only trusted services and private endpoints.",
        llm_confidence="Medium", verification_status="Flagged", iso_27001="A.8.24 Cryptography",
        cis_control="CIS 8.5", mitre_attck="T1552", is_catalogued_misconfig="No"),
    "AZ-SQL-TDE": dict(service="SQL", resource_name="sql-cloudguardian-lab", region="Central US",
        check_id="sql_tde_check", title="TDE status needs manual confirmation",
        description="The scanner could not confirm Transparent Data Encryption is enforced.",
        severity="Medium", source_tool="ScoutSuite", risk_score=48, cvss="", exposure="Internal",
        blast_radius="Resource", remediation="Confirm TDE is enabled on the SQL database (on by default).",
        llm_confidence="Low", verification_status="Needs Review", iso_27001="A.8.24 Cryptography",
        cis_control="CIS 4.5", mitre_attck="T1005", is_catalogued_misconfig="No"),
    "AZ-MON-ACTLOG-ALERT": dict(service="Monitoring", resource_name="rg-cloudguardian-lab", region="Central US",
        check_id="activity_log_alert_missing", title="No activity-log alert for config changes",
        description="No alert exists for security-relevant control-plane operations.",
        severity="Low", source_tool="Steampipe", risk_score=35, cvss="4.0", exposure="Internal",
        blast_radius="Subscription", remediation="Create activity-log alerts for NSG/firewall rule changes.",
        llm_confidence="Medium", verification_status="Verified", iso_27001="A.8.16 Monitoring",
        cis_control="CIS 5.2", mitre_attck="T1562", is_catalogued_misconfig="No"),
    "AZ-IAM-MI-MISSING": dict(service="Identity", resource_name="vm-web-cloudguardian", region="Central US",
        check_id="managed_identity_missing", title="VM has no managed identity",
        description="The VM authenticates without a managed identity.",
        severity="Low", source_tool="ScoutSuite", risk_score=30, cvss="3.5", exposure="Internal",
        blast_radius="Resource", remediation="Assign a system-assigned managed identity with least-privilege RBAC.",
        llm_confidence="Medium", verification_status="Verified", iso_27001="A.5.16 Identity management",
        cis_control="CIS 1.21", mitre_attck="T1078", is_catalogued_misconfig="No"),
}

AWS = {
    "AWS-S3-PUBLIC": dict(service="S3", resource_name="cg-public-assets", region="us-east-1",
        check_id="s3_bucket_public_read", title="S3 bucket allows public read",
        description="Bucket policy/ACL grants anonymous read to all objects.",
        severity="Critical", source_tool="Prowler", risk_score=96, cvss="9.1", exposure="Public",
        blast_radius="Account", remediation="Enable S3 Block Public Access at account and bucket level; remove public policies.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.3 Access restriction",
        cis_control="CIS 2.1.5", mitre_attck="T1530", is_catalogued_misconfig="Yes"),
    "AWS-EC2-SSH-OPEN": dict(service="EC2", resource_name="sg-web-0a1b2c", region="us-east-1",
        check_id="sg_ssh_open_world", title="Security group opens SSH to 0.0.0.0/0",
        description="An inbound SG rule permits TCP 22 from anywhere.",
        severity="Critical", source_tool="Prowler", risk_score=92, cvss="8.6", exposure="Public",
        blast_radius="Resource", remediation="Restrict SSH to a known CIDR or use SSM Session Manager.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.20 Network security",
        cis_control="CIS 5.2", mitre_attck="T1110", is_catalogued_misconfig="Yes"),
    "AWS-IAM-ADMIN": dict(service="IAM", resource_name="svc-deploy", region="global",
        check_id="iam_user_admin_policy", title="IAM user has AdministratorAccess",
        description="A non-break-glass IAM user is attached to AdministratorAccess.",
        severity="High", source_tool="ScoutSuite", risk_score=78, cvss="7.5", exposure="Internal",
        blast_radius="Account", remediation="Replace broad policy with scoped permissions; use a role with MFA.",
        llm_confidence="Medium", verification_status="Flagged", iso_27001="A.5.15 Access control",
        cis_control="CIS 1.16", mitre_attck="T1078", is_catalogued_misconfig="Yes"),
    "AWS-RDS-UNENCRYPTED": dict(service="RDS", resource_name="cg-orders-db", region="us-east-1",
        check_id="rds_storage_unencrypted", title="RDS storage is unencrypted",
        description="The database instance has no storage encryption.",
        severity="High", source_tool="Prowler", risk_score=74, cvss="6.8", exposure="Internal",
        blast_radius="Resource", remediation="Recreate from an encrypted snapshot with KMS storage encryption.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.24 Cryptography",
        cis_control="CIS 2.3.1", mitre_attck="T1005", is_catalogued_misconfig="Yes"),
    "AWS-CLOUDTRAIL-OFF": dict(service="CloudTrail", resource_name="(account)", region="global",
        check_id="cloudtrail_not_enabled", title="CloudTrail not enabled in all regions",
        description="Management events are not recorded across all regions.",
        severity="Medium", source_tool="Steampipe", risk_score=58, cvss="5.5", exposure="Internal",
        blast_radius="Account", remediation="Create a multi-region trail with log-file validation to a protected bucket.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.8.15 Logging",
        cis_control="CIS 3.1", mitre_attck="T1562", is_catalogued_misconfig="Yes"),
    "AWS-ROOT-KEYS": dict(service="IAM", resource_name="root", region="global",
        check_id="root_access_keys_present", title="Root account has active access keys",
        description="Long-lived access keys exist on the root user.",
        severity="Critical", source_tool="Prowler", risk_score=89, cvss="9.0", exposure="Internal",
        blast_radius="Account", remediation="Delete all root access keys; enforce MFA on root; use roles for automation.",
        llm_confidence="High", verification_status="Verified", iso_27001="A.5.17 Authentication info",
        cis_control="CIS 1.4", mitre_attck="T1078", is_catalogued_misconfig="No"),
}

# Which findings are FAILing at each stage (everything else = PASS; TDE = MANUAL).
AZ_FAIL = {
    "Baseline": {"AZ-MON-ACTLOG-ALERT", "AZ-IAM-MI-MISSING"},
    "After misconfig": {"AZ-STG-PUBLIC-CONTAINER", "AZ-NET-SSH-OPEN", "AZ-SQL-FW-ALLOWALL",
        "AZ-VM-PWD-AUTH", "AZ-STG-PUBNET", "AZ-STG-LOG-OFF", "AZ-KV-PUBLIC",
        "AZ-MON-ACTLOG-ALERT", "AZ-IAM-MI-MISSING"},
    "After remediation": {"AZ-NET-SSH-OPEN", "AZ-VM-PWD-AUTH", "AZ-IAM-MI-MISSING", "AZ-MON-ACTLOG-ALERT"},
}
AWS_FAIL = {
    "Baseline": set(),
    "After misconfig": {"AWS-S3-PUBLIC", "AWS-EC2-SSH-OPEN", "AWS-IAM-ADMIN",
        "AWS-RDS-UNENCRYPTED", "AWS-CLOUDTRAIL-OFF", "AWS-ROOT-KEYS"},
    "After remediation": {"AWS-EC2-SSH-OPEN", "AWS-IAM-ADMIN"},
}

STAGES = [
    ("Baseline", 1),
    ("After misconfig", 1),
    ("After remediation", 3),
]
DATES = {
    ("Azure", "Baseline"): "2026-06-20", ("Azure", "After misconfig"): "2026-06-27",
    ("Azure", "After remediation"): "2026-07-12",
    ("AWS", "Baseline"): "2026-06-21", ("AWS", "After misconfig"): "2026-06-28",
    ("AWS", "After remediation"): "2026-07-13",
}
ACCOUNTS = {"Azure": "sub-0f3a2b", "AWS": "111122223333"}


def emit(cloud, checks, fail_map, out_dir):
    for stage, week in STAGES:
        stage_slug = stage.lower().replace(" ", "-")
        scan_id = f"{cloud.lower()}-w{week}-{stage_slug}"
        fname = f"{cloud.lower()}_w{week}_{stage_slug}.csv"
        path = os.path.join(out_dir, fname)
        failing = fail_map[stage]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=FINDING_FIELDS)
            w.writeheader()
            for fid, attrs in checks.items():
                if attrs["check_id"] == "sql_tde_check":
                    status = "MANUAL"
                else:
                    status = "FAIL" if fid in failing else "PASS"
                row = {
                    "cloud": cloud, "week": week, "scan_stage": stage,
                    "scan_id": scan_id, "captured_at": DATES[(cloud, stage)],
                    "finding_id": fid, "account_id": ACCOUNTS[cloud], "status": status,
                    "detected_by": DETECTED_BY.get(fid, attrs.get("source_tool", "")),
                }
                row.update(attrs)
                w.writerow(row)
        print("wrote", path)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.abspath(os.path.join(here, "..", "reports"))
    os.makedirs(out_dir, exist_ok=True)
    emit("Azure", AZURE, AZ_FAIL, out_dir)
    emit("AWS", AWS, AWS_FAIL, out_dir)
    print("done")


if __name__ == "__main__":
    main()
