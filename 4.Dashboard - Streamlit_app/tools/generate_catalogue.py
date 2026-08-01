"""
tools/generate_catalogue.py
===========================
Writes the three reference tables into ../catalogue.

These are hand-maintained in real use — this script just seeds them with a
worked example matching the sample reports, and documents the columns.

Run:  python tools/generate_catalogue.py
"""

from __future__ import annotations

import csv
import os

TOGGLES = [
    # toggle_id, cloud, toggle_name, category, expected_finding, severity, rationale, revert
    ("AZ-T01", "Azure", "misconfig_storage_public_container", "Storage",
     "AZ-STG-PUBLIC-CONTAINER", "Critical",
     "Simulates the classic public bucket that repeatedly fails ISO audits.",
     "Set misconfig_storage_public_container = false and re-apply."),
    ("AZ-T02", "Azure", "misconfig_ssh_open_to_internet", "Networking",
     "AZ-NET-SSH-OPEN", "Critical",
     "Exposes management plane to the internet; primary brute-force vector.",
     "Set misconfig_ssh_open_to_internet = false and re-apply."),
    ("AZ-T03", "Azure", "misconfig_sql_allow_all_ips", "Networking",
     "AZ-SQL-FW-ALLOWALL", "Critical",
     "Database reachable from any host, mirroring a common lift-and-shift error.",
     "Set misconfig_sql_allow_all_ips = false and re-apply."),
    ("AZ-T04", "Azure", "misconfig_vm_allow_password_auth", "Identity",
     "AZ-VM-PWD-AUTH", "High",
     "Weakens SSH to password auth, enabling credential stuffing.",
     "Set misconfig_vm_allow_password_auth = false and re-apply."),
    ("AZ-T05", "Azure", "misconfig_storage_allow_public_network_access", "Networking",
     "AZ-STG-PUBNET", "High",
     "Removes network restriction from the storage account.",
     "Set misconfig_storage_allow_public_network_access = false and re-apply."),
    ("AZ-T06", "Azure", "misconfig_disable_storage_logging", "Logging",
     "AZ-STG-LOG-OFF", "Medium",
     "Removes the audit trail, covering the 'missing logging' control.",
     "Set misconfig_disable_storage_logging = false and re-apply."),
    ("AZ-T07", "Azure", "misconfig_keyvault_public_access", "Encryption",
     "AZ-KV-PUBLIC", "High",
     "Key material reachable from any network.",
     "Set misconfig_keyvault_public_access = false and re-apply."),
    ("AZ-T08", "Azure", "(no toggle) managed identity absent", "Identity",
     "AZ-IAM-MI-MISSING", "Low",
     "Baseline gap retained deliberately to test absence-of-control detection.",
     "Assign a system-assigned managed identity to the VM."),
    ("AZ-T09", "Azure", "(no toggle) activity-log alert absent", "Monitoring",
     "AZ-MON-ACTLOG-ALERT", "Low",
     "Baseline gap retained to test detection of missing monitoring.",
     "Create an activity-log alert for NSG and firewall changes."),
    ("AZ-T10", "Azure", "(manual) SQL TDE verification", "Encryption",
     "AZ-SQL-TDE", "Medium",
     "TDE is on by default; retained to show MANUAL-status handling.",
     "Confirm TDE enabled on the SQL database."),
    ("AWS-T01", "AWS", "misconfig_s3_public_read", "Storage",
     "AWS-S3-PUBLIC", "Critical",
     "Public object storage, the AWS twin of the Azure container toggle.",
     "Enable S3 Block Public Access at account and bucket level."),
    ("AWS-T02", "AWS", "misconfig_sg_ssh_open", "Networking",
     "AWS-EC2-SSH-OPEN", "Critical",
     "Security group open on 22 to the world.",
     "Restrict the inbound rule to a known CIDR."),
    ("AWS-T03", "AWS", "misconfig_iam_admin_policy", "Identity",
     "AWS-IAM-ADMIN", "High",
     "Over-privileged IAM user, the 'over-privileged role' control.",
     "Detach AdministratorAccess and attach a scoped policy."),
    ("AWS-T04", "AWS", "misconfig_rds_unencrypted", "Encryption",
     "AWS-RDS-UNENCRYPTED", "High",
     "Unencrypted database storage at rest.",
     "Recreate from an encrypted snapshot with KMS."),
    ("AWS-T05", "AWS", "misconfig_disable_cloudtrail", "Logging",
     "AWS-CLOUDTRAIL-OFF", "Medium",
     "Removes multi-region audit logging.",
     "Create a multi-region trail with log-file validation."),
    ("AWS-T06", "AWS", "(no toggle) root access keys", "Identity",
     "AWS-ROOT-KEYS", "Critical",
     "Baseline gap retained; long-lived root credentials.",
     "Delete root access keys and enforce MFA."),
]

ATTACK_PATHS = [
    # path_id, path_name, cloud, severity, step_order, node_label, node_type, finding_id, note
    ("AP-01", "Internet to database exfiltration", "Azure", "Critical", 1,
     "Internet", "entry", "AZ-NET-SSH-OPEN",
     "SSH is reachable from any address, so the attacker can attempt credential attacks against the web VM."),
    ("AP-01", "Internet to database exfiltration", "Azure", "Critical", 2,
     "Web VM", "pivot", "AZ-VM-PWD-AUTH",
     "Password authentication is enabled, so a successful guess yields an interactive session."),
    ("AP-01", "Internet to database exfiltration", "Azure", "Critical", 3,
     "SQL database", "target", "AZ-SQL-FW-ALLOWALL",
     "The SQL firewall permits every address, so the compromised host can connect and read data."),

    ("AP-02", "Anonymous data harvesting", "Azure", "Critical", 1,
     "Internet", "entry", "AZ-STG-PUBNET",
     "The storage account accepts traffic from any network."),
    ("AP-02", "Anonymous data harvesting", "Azure", "Critical", 2,
     "Blob container", "target", "AZ-STG-PUBLIC-CONTAINER",
     "Anonymous read is permitted, so objects can be downloaded without credentials."),
    ("AP-02", "Anonymous data harvesting", "Azure", "Critical", 3,
     "Undetected exfiltration", "target", "AZ-STG-LOG-OFF",
     "Diagnostic logging is disabled, so the download leaves no audit record."),

    ("AP-03", "Credential theft to privilege escalation", "AWS", "Critical", 1,
     "Internet", "entry", "AWS-EC2-SSH-OPEN",
     "The security group exposes SSH to the world."),
    ("AP-03", "Credential theft to privilege escalation", "AWS", "Critical", 2,
     "IAM user", "pivot", "AWS-IAM-ADMIN",
     "A reachable IAM user holds AdministratorAccess, granting full control if compromised."),
    ("AP-03", "Credential theft to privilege escalation", "AWS", "Critical", 3,
     "Account takeover", "target", "AWS-ROOT-KEYS",
     "Active root access keys allow persistence that survives remediation of the IAM user."),

    ("AP-04", "Secret disclosure", "Azure", "High", 1,
     "Internet", "entry", "AZ-KV-PUBLIC",
     "Key Vault has no network restriction, so the endpoint is reachable."),
    ("AP-04", "Secret disclosure", "Azure", "High", 2,
     "Stored secrets", "target", "AZ-IAM-MI-MISSING",
     "Without managed identity, applications hold static credentials that are worth stealing."),
]

DPDP_MAP = [
    ("A.8.3 Access restriction", "S.8(5)",
     "Reasonable security safeguards to prevent personal data breach"),
    ("A.8.20 Network security", "S.8(5)",
     "Reasonable security safeguards to prevent personal data breach"),
    ("A.8.24 Cryptography", "S.8(5)",
     "Protection of personal data at rest and in transit"),
    ("A.8.15 Logging", "S.8(6)",
     "Ability to detect and report a personal data breach to the Board and affected principals"),
    ("A.8.16 Monitoring", "S.8(6)",
     "Detection of breach events supporting the notification obligation"),
    ("A.8.5 Secure authentication", "S.8(5)",
     "Access control safeguards over systems processing personal data"),
    ("A.5.15 Access control", "S.8(5)",
     "Least-privilege access to personal data"),
    ("A.5.16 Identity management", "S.8(5)",
     "Accountable identity for every principal accessing personal data"),
    ("A.5.17 Authentication info", "S.8(5)",
     "Protection of credentials used to access personal data"),
]


def write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.abspath(os.path.join(here, "..", "catalogue"))
    os.makedirs(out, exist_ok=True)

    write(os.path.join(out, "toggles.csv"),
          ["toggle_id", "cloud", "toggle_name", "category", "expected_finding",
           "severity", "rationale", "revert"], TOGGLES)

    write(os.path.join(out, "attack_paths.csv"),
          ["path_id", "path_name", "cloud", "severity", "step_order",
           "node_label", "node_type", "finding_id", "note"], ATTACK_PATHS)

    write(os.path.join(out, "dpdp_map.csv"),
          ["iso_27001", "dpdp_section", "dpdp_obligation"], DPDP_MAP)
    print("done")


if __name__ == "__main__":
    main()
