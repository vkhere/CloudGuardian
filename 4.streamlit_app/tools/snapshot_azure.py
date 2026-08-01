"""
tools/snapshot_azure.py
=======================
Captures your live Azure environment to data/azure_snapshot.json for the
console's Environment page: resource inventory, health, Terraform drift,
current misconfiguration toggles and an estimated cost.

WHY A SCRIPT AND NOT LIVE CALLS FROM THE DASHBOARD
    Streamlit re-runs the entire script on every click. Calling Azure each
    time would be slow, would hammer the API, and would break completely if
    the network is unavailable. Capturing to a file keeps the dashboard fast
    and lets it work offline.

WHAT IT NEEDS
    * Azure CLI installed and signed in:      az login
    * Read access to the resource group (Reader is enough)
    * Optional: Terraform installed, and the path to your Terraform folder,
      for drift detection

USAGE
    python tools/snapshot_azure.py
    python tools/snapshot_azure.py --resource-group rg-cloudguardian-lab \
        --terraform-dir C:\\projects\\azure-3tier-terraform

NOTHING IS MODIFIED. Every Azure call is read-only, and terraform plan never
changes infrastructure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime

# Rough INR/day estimates for a free-tier lab. Deliberately a static table:
# the Azure consumption API is frequently unavailable on student subscriptions,
# and a predictable estimate is more useful here than an API that may 403.
COST_PER_DAY_INR = {
    "Microsoft.Compute/virtualMachines": 45.0,
    "Microsoft.Sql/servers/databases": 22.0,
    "Microsoft.Storage/storageAccounts": 3.0,
    "Microsoft.KeyVault/vaults": 1.0,
    "Microsoft.OperationalInsights/workspaces": 3.0,
    "Microsoft.Network/publicIPAddresses": 2.5,
}

HEALTHY_STATES = {"running", "online", "available", "succeeded", "ready"}


def run(cmd: list[str], cwd: str | None = None, timeout: int = 180) -> tuple[int, str, str]:
    """Run a command, returning (exit code, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]} timed out after {timeout}s"


def az_json(args: list[str]) -> object | None:
    """Run an az command that returns JSON."""
    exe = "az.cmd" if os.name == "nt" else "az"
    code, out, err = run([exe] + args + ["-o", "json"])
    if code != 0:
        print(f"  ! az {' '.join(args)} failed: {err.strip()[:160]}")
        return None
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError:
        return None


def collect_resources(resource_group: str) -> list[dict]:
    print("Listing resources...")
    items = az_json(["resource", "list", "-g", resource_group]) or []
    resources = []
    for r in items:
        rtype = r.get("type", "")
        state = "Succeeded"
        # VMs report a real power state; everything else uses provisioning state.
        if rtype == "Microsoft.Compute/virtualMachines":
            iv = az_json(["vm", "get-instance-view", "-g", resource_group,
                          "-n", r.get("name", "")])
            if iv:
                statuses = [s.get("displayStatus", "")
                            for s in (iv.get("instanceView", {}) or {}).get("statuses", [])]
                power = [s for s in statuses if s.startswith("VM ")]
                state = power[0].replace("VM ", "").title() if power else "Unknown"
        else:
            state = (r.get("provisioningState") or "Succeeded")
        resources.append({
            "name": r.get("name", ""),
            "type": rtype.split("/")[-1] if rtype else "",
            "full_type": rtype,
            "location": r.get("location", ""),
            "state": state,
            "healthy": state.strip().lower() in HEALTHY_STATES,
            "tags": r.get("tags") or {},
        })
    print(f"  found {len(resources)} resources")
    return resources


def collect_drift(terraform_dir: str | None) -> dict:
    """
    Run `terraform plan -detailed-exitcode`. Exit code 2 means the deployed
    state has diverged from the code. Nothing is applied.
    """
    if not terraform_dir or not os.path.isdir(terraform_dir):
        return {"status": "not_checked", "checked_at": "", "changes": [],
                "note": "No Terraform directory supplied."}

    print("Checking Terraform drift (read-only plan)...")
    exe = "terraform.exe" if os.name == "nt" else "terraform"
    code, out, err = run([exe, "plan", "-detailed-exitcode", "-no-color",
                          "-input=false", "-lock=false"],
                         cwd=terraform_dir, timeout=600)

    if code == 0:
        return {"status": "in_sync", "checked_at": _now(), "changes": []}
    if code not in (2,):
        return {"status": "error", "checked_at": _now(), "changes": [],
                "note": (err or out).strip()[:400]}

    # Exit code 2: parse the human-readable plan for changed resources.
    changes = []
    for line in out.splitlines():
        m = re.match(r"\s*# (\S+) (?:will be|has been|must be) (.+)", line)
        if m:
            changes.append({
                "resource": m.group(1),
                "change": m.group(2).strip().rstrip(":").capitalize(),
                "detail": "Deployed state differs from Terraform configuration.",
            })
    if not changes:
        changes.append({"resource": "(see plan output)", "change": "Drift detected",
                        "detail": "terraform plan reported changes; run it manually for detail."})
    print(f"  drift: {len(changes)} resource(s)")
    return {"status": "drifted", "checked_at": _now(), "changes": changes}


def collect_toggles(terraform_dir: str | None) -> dict:
    """Read the current misconfiguration toggle values from terraform.tfvars."""
    if not terraform_dir:
        return {}
    path = os.path.join(terraform_dir, "terraform.tfvars")
    if not os.path.exists(path):
        return {}
    toggles = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith("misconfig_"):
                continue  # commented-out lines count as off
            m = re.match(r"(misconfig_\w+)\s*=\s*(true|false)", stripped)
            if m:
                toggles[m.group(1)] = m.group(2) == "true"
    return toggles


def estimate_cost(resources: list[dict]) -> dict:
    today = sum(COST_PER_DAY_INR.get(r.get("full_type", ""), 0.5) for r in resources)
    return {"currency": "INR", "today": round(today, 2),
            "month_to_date": round(today * datetime.now().day, 2),
            "basis": "static per-resource estimate, not billing data"}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture Azure environment for the console")
    ap.add_argument("--resource-group", default="rg-cloudguardian-lab")
    ap.add_argument("--terraform-dir", default=None,
                    help="Path to your Terraform project, for drift and toggle state")
    ap.add_argument("--out", default=os.path.join("data", "azure_snapshot.json"))
    args = ap.parse_args()

    print(f"CloudGuardian environment snapshot")
    print(f"  resource group : {args.resource_group}")
    print(f"  terraform dir  : {args.terraform_dir or '(not supplied)'}\n")

    sub = az_json(["account", "show"])
    if sub is None:
        print("\nCould not reach Azure. Run 'az login' first, then retry.")
        return 1

    resources = collect_resources(args.resource_group)
    snapshot = {
        "cloud": "Azure",
        "captured_at": _now(),
        "subscription": sub.get("id", ""),
        "subscription_name": sub.get("name", ""),
        "resource_group": args.resource_group,
        "resources": resources,
        "drift": collect_drift(args.terraform_dir),
        "toggles": collect_toggles(args.terraform_dir),
        "estimated_cost": estimate_cost(resources),
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)

    print(f"\nWrote {args.out}")
    print("Click 'Reload' in the console sidebar to pick it up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
