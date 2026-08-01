#!/usr/bin/env python3
"""
CloudGuardian - Automatic Compliance Crosswalk Generator
===========================================================
Maps every Prowler finding to four security/compliance frameworks:
    - ISO 27001:2022 Annex A
    - HIPAA
    - NIST CSF 2.0
    - CIS AWS Foundations Benchmark (latest version present)
    - DPDP Act 2023 (India) -- via a manually-curated crosswalk CSV,
      since DPDP is not a built-in Prowler framework.

HOW IT WORKS
------------
Prowler's raw output CSV already tags every check with its ISO27001,
HIPAA, NIST-CSF, and CIS references inside the COMPLIANCE column. This
script parses that column automatically -- no manual mapping needed for
those four. For DPDP Act 2023, it joins against a separate crosswalk CSV
(Check_ID, ISO_Control, DPDP_Section, Relevance, Justification) that you
maintain by hand, since DPDP has no official machine-readable mapping.

USAGE
-----
Run with no arguments to be walked through file selection with a GUI
file browser:

    python3 crosswalk_generator.py

Or run non-interactively by passing paths directly:

    python3 crosswalk_generator.py --prowler-csv path/to/scan.csv \
        --dpdp-crosswalk path/to/dpdp_crosswalk.csv \
        --output-dir path/to/output_folder

REQUIRED FILES
--------------
1. Prowler raw findings CSV (REQUIRED)
   The main "prowler-output-<account>-<timestamp>.csv" file produced by
   a normal `prowler aws` run. Must contain a COMPLIANCE column.

2. DPDP crosswalk CSV (OPTIONAL, recommended)
   A CSV with columns: Check_ID, ISO_Control, DPDP_Section, Relevance,
   Justification. If skipped, DPDP columns are filled with "Not Assessed"
   for every finding and you'll need to add mappings by hand later.
"""

import csv
import os
import sys
import argparse
from datetime import datetime
from collections import defaultdict, Counter

# --------------------------------------------------------------------------
# Step 0: File selection (GUI browser, with CLI-argument fallback)
# --------------------------------------------------------------------------

REQUIRED_FILES_MESSAGE = """
================================================================================
 CloudGuardian Compliance Crosswalk Generator
================================================================================
This script needs the following file(s) to run:

  1) REQUIRED  - Prowler raw findings CSV
                 (e.g. prowler-output-<account_id>-<timestamp>.csv)
                 This is the normal Prowler scan output, and must have a
                 "COMPLIANCE" column. It already contains built-in mappings
                 for ISO 27001, HIPAA, NIST CSF, and CIS per finding.

  2) OPTIONAL  - DPDP Act 2023 crosswalk CSV
                 (e.g. dpdp_crosswalk.csv)
                 Columns expected: Check_ID, ISO_Control, DPDP_Section,
                 Relevance, Justification.
                 DPDP has no official Prowler mapping, so this file supplies
                 it. If you don't have one yet, you can skip this step and
                 the script will mark DPDP mapping as "Not Assessed" for
                 every finding so you can fill it in later.

You will now be asked to browse for these files.
================================================================================
"""


def select_file_gui(title, filetypes, required=True):
    """Open a native file-browser dialog and return the chosen path.
    Falls back to a typed path if no GUI/display is available."""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        root.destroy()
        if path:
            return path
        if required:
            print("No file selected. This file is required - please try again.")
            return select_file_gui(title, filetypes, required=required)
        return None
    except Exception:
        # No display / tkinter unavailable -> fall back to typed input
        print(f"[GUI file browser unavailable] {title}")
        prompt = "Enter full path to file" + ("" if required else " (leave blank to skip)") + ": "
        path = input(prompt).strip().strip('"')
        if not path and not required:
            return None
        if not path or not os.path.isfile(path):
            print("File not found, try again.")
            return select_file_gui(title, filetypes, required=required)
        return path


def select_folder_gui(title, default_path):
    """Open a native folder-browser dialog and return the chosen path."""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askdirectory(title=title, initialdir=default_path)
        root.destroy()
        return path if path else default_path
    except Exception:
        typed = input(f"Enter output folder path [default: {default_path}]: ").strip()
        return typed if typed else default_path


# --------------------------------------------------------------------------
# Step 1: Parse the COMPLIANCE column for built-in framework references
# --------------------------------------------------------------------------

def parse_compliance_field(compliance_str):
    """Turn Prowler's raw COMPLIANCE string into {framework_name: [refs]}.

    Prowler format looks like:
      'CIS-6.0: 2.19 | ISO27001-2022: A.8.3 | HIPAA: 164.312(a)(1) | ...'
    """
    result = defaultdict(list)
    if not compliance_str:
        return result
    for segment in compliance_str.split("|"):
        segment = segment.strip()
        if ":" not in segment:
            continue
        framework, refs = segment.split(":", 1)
        framework = framework.strip()
        refs = [r.strip() for r in refs.split(",") if r.strip()]
        result[framework].extend(refs)
    return result


def pick_best_cis_version(framework_dict):
    """Prowler tags multiple CIS versions per check (CIS-1.4 ... CIS-7.0).
    Pick the highest version number so the crosswalk shows one clean value."""
    cis_versions = []
    for fw in framework_dict:
        if fw.startswith("CIS-"):
            try:
                ver_str = fw.replace("CIS-", "")
                ver_tuple = tuple(int(x) for x in ver_str.split("."))
                cis_versions.append((ver_tuple, fw))
            except ValueError:
                continue
    if not cis_versions:
        return "Not Mapped", []
    cis_versions.sort(reverse=True)
    best_fw = cis_versions[0][1]
    return best_fw, framework_dict[best_fw]


def extract_framework_refs(framework_dict, *candidate_names):
    """Return refs for the first matching framework name found (in priority order)."""
    for name in candidate_names:
        if name in framework_dict:
            return framework_dict[name]
    return []


# --------------------------------------------------------------------------
# Step 2: Load the DPDP crosswalk (Check_ID -> DPDP mapping)
# --------------------------------------------------------------------------

def load_dpdp_crosswalk(path):
    """Returns {check_id: [ {ISO_Control, DPDP_Section, Relevance, Justification}, ... ]}
    A check can appear more than once if it maps to multiple ISO/DPDP clauses."""
    mapping = defaultdict(list)
    if not path:
        return mapping
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            check_id = row.get("Check_ID", "").strip()
            if not check_id:
                continue
            mapping[check_id].append({
                "ISO_Control": row.get("ISO_Control", "").strip(),
                "DPDP_Section": row.get("DPDP_Section", "").strip(),
                "Relevance": row.get("Relevance", "").strip(),
                "Justification": row.get("Justification", "").strip(),
            })
    return mapping


# --------------------------------------------------------------------------
# Step 3: Build the master crosswalk
# --------------------------------------------------------------------------

def build_crosswalk(prowler_csv_path, dpdp_map):
    with open(prowler_csv_path, encoding="utf-8") as f:
        # Prowler CSVs are semicolon-delimited
        reader = csv.DictReader(f, delimiter=";")
        rows = list(reader)

    if not rows:
        raise ValueError("Prowler CSV appears to be empty.")
    if "COMPLIANCE" not in rows[0]:
        raise ValueError("This CSV has no COMPLIANCE column - is it a raw Prowler output file?")

    crosswalk_rows = []
    for r in rows:
        fw = parse_compliance_field(r.get("COMPLIANCE", ""))

        iso_refs = extract_framework_refs(fw, "ISO27001-2022", "ISO27001-2013")
        hipaa_refs = extract_framework_refs(fw, "HIPAA")
        nist_refs = extract_framework_refs(fw, "NIST-CSF-2.0", "NIST-CSF-1.1")
        cis_version, cis_refs = pick_best_cis_version(fw)

        check_id = r.get("CHECK_ID", "")
        dpdp_entries = dpdp_map.get(check_id, [])

        if dpdp_entries:
            for entry in dpdp_entries:
                crosswalk_rows.append({
                    "CHECK_ID": check_id,
                    "CHECK_TITLE": r.get("CHECK_TITLE", ""),
                    "SEVERITY": r.get("SEVERITY", ""),
                    "STATUS": r.get("STATUS", ""),
                    "SERVICE_NAME": r.get("SERVICE_NAME", ""),
                    "RESOURCE_UID": r.get("RESOURCE_UID", ""),
                    "ISO27001_Annex_A": ", ".join(iso_refs) if iso_refs else "Not Mapped",
                    "HIPAA": ", ".join(hipaa_refs) if hipaa_refs else "Not Mapped",
                    "NIST_CSF_2_0": ", ".join(nist_refs) if nist_refs else "Not Mapped",
                    "CIS_Benchmark": f"{cis_version}: " + ", ".join(cis_refs) if cis_refs else "Not Mapped",
                    "DPDP_Section": entry["DPDP_Section"] or "Not Mapped",
                    "DPDP_Relevance": entry["Relevance"] or "Not Assessed",
                    "DPDP_Justification": entry["Justification"] or "",
                })
        else:
            crosswalk_rows.append({
                "CHECK_ID": check_id,
                "CHECK_TITLE": r.get("CHECK_TITLE", ""),
                "SEVERITY": r.get("SEVERITY", ""),
                "STATUS": r.get("STATUS", ""),
                "SERVICE_NAME": r.get("SERVICE_NAME", ""),
                "RESOURCE_UID": r.get("RESOURCE_UID", ""),
                "ISO27001_Annex_A": ", ".join(iso_refs) if iso_refs else "Not Mapped",
                "HIPAA": ", ".join(hipaa_refs) if hipaa_refs else "Not Mapped",
                "NIST_CSF_2_0": ", ".join(nist_refs) if nist_refs else "Not Mapped",
                "CIS_Benchmark": f"{cis_version}: " + ", ".join(cis_refs) if cis_refs else "Not Mapped",
                "DPDP_Section": "Not Assessed",
                "DPDP_Relevance": "Not Assessed",
                "DPDP_Justification": "No entry in dpdp_crosswalk.csv yet - add one if this check is relevant to personal-data handling.",
            })

    return crosswalk_rows


# --------------------------------------------------------------------------
# Step 4: Write outputs (full CSV, FAIL-only CSV, markdown summary)
# --------------------------------------------------------------------------

FIELDNAMES = [
    "CHECK_ID", "CHECK_TITLE", "SEVERITY", "STATUS", "SERVICE_NAME", "RESOURCE_UID",
    "ISO27001_Annex_A", "HIPAA", "NIST_CSF_2_0", "CIS_Benchmark",
    "DPDP_Section", "DPDP_Relevance", "DPDP_Justification",
]


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def write_summary_md(rows, path, source_file):
    total = len(rows)
    unique_checks = len({r["CHECK_ID"] for r in rows})
    fail_rows = [r for r in rows if r["STATUS"] == "FAIL"]

    def coverage(field):
        mapped = sum(1 for r in rows if r[field] not in ("Not Mapped", "Not Assessed"))
        return mapped, total, round(100 * mapped / total, 1) if total else 0

    iso_c = coverage("ISO27001_Annex_A")
    hipaa_c = coverage("HIPAA")
    nist_c = coverage("NIST_CSF_2_0")
    cis_c = coverage("CIS_Benchmark")
    dpdp_c = coverage("DPDP_Section")

    lines = [
        "# Compliance Crosswalk Summary",
        "",
        f"**Source scan:** `{os.path.basename(source_file)}`",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total crosswalk rows:** {total}  (unique checks: {unique_checks})",
        f"**FAIL findings:** {len(fail_rows)}",
        "",
        "## Framework coverage (how many rows have a mapping)",
        "",
        "| Framework | Mapped | Total | Coverage |",
        "|---|---|---|---|",
        f"| ISO 27001:2022 Annex A | {iso_c[0]} | {iso_c[1]} | {iso_c[2]}% |",
        f"| HIPAA | {hipaa_c[0]} | {hipaa_c[1]} | {hipaa_c[2]}% |",
        f"| NIST CSF 2.0 | {nist_c[0]} | {nist_c[1]} | {nist_c[2]}% |",
        f"| CIS AWS Foundations | {cis_c[0]} | {cis_c[1]} | {cis_c[2]}% |",
        f"| DPDP Act 2023 | {dpdp_c[0]} | {dpdp_c[1]} | {dpdp_c[2]}% |",
        "",
        "> ISO 27001, HIPAA, NIST CSF and CIS are auto-extracted from Prowler's "
        "built-in COMPLIANCE metadata - coverage should be near 100%. "
        "DPDP coverage depends entirely on how many checks exist in your "
        "`dpdp_crosswalk.csv` - extend that file to raise this number.",
        "",
        "## FAIL findings without a DPDP mapping yet",
        "",
    ]
    missing_dpdp_fails = [r for r in fail_rows if r["DPDP_Relevance"] == "Not Assessed"]
    if missing_dpdp_fails:
        lines.append("| Check ID | Title | Severity |")
        lines.append("|---|---|---|")
        seen = set()
        for r in missing_dpdp_fails:
            if r["CHECK_ID"] in seen:
                continue
            seen.add(r["CHECK_ID"])
            lines.append(f"| `{r['CHECK_ID']}` | {r['CHECK_TITLE']} | {r['SEVERITY']} |")
    else:
        lines.append("None - every FAIL finding has a DPDP assessment. 🎉")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate a compliance crosswalk from a Prowler scan.")
    parser.add_argument("--prowler-csv", help="Path to raw Prowler findings CSV")
    parser.add_argument("--dpdp-crosswalk", help="Path to dpdp_crosswalk.csv")
    parser.add_argument("--output-dir", help="Folder to write outputs into")
    args = parser.parse_args()

    print(REQUIRED_FILES_MESSAGE)

    prowler_csv = args.prowler_csv or select_file_gui(
        "Select the Prowler raw findings CSV (REQUIRED)",
        [("CSV files", "*.csv"), ("All files", "*.*")],
        required=True,
    )

    dpdp_csv = args.dpdp_crosswalk
    if dpdp_csv is None:
        print("\nNow select your DPDP crosswalk CSV. Click Cancel to skip if you don't have one yet.")
        dpdp_csv = select_file_gui(
            "Select dpdp_crosswalk.csv (OPTIONAL - Cancel to skip)",
            [("CSV files", "*.csv"), ("All files", "*.*")],
            required=False,
        )

    default_out = args.output_dir or os.path.dirname(prowler_csv)
    output_dir = args.output_dir or select_folder_gui("Select output folder", default_out)
    os.makedirs(output_dir, exist_ok=True)

    print(f"\nProwler CSV : {prowler_csv}")
    print(f"DPDP CSV    : {dpdp_csv or '(skipped - DPDP will be marked Not Assessed)'}")
    print(f"Output dir  : {output_dir}\n")
    print("Building crosswalk...")

    dpdp_map = load_dpdp_crosswalk(dpdp_csv)
    rows = build_crosswalk(prowler_csv, dpdp_map)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_csv_path = os.path.join(output_dir, f"compliance_crosswalk_full_{timestamp}.csv")
    fail_csv_path = os.path.join(output_dir, f"compliance_crosswalk_FAILonly_{timestamp}.csv")
    summary_md_path = os.path.join(output_dir, f"compliance_crosswalk_summary_{timestamp}.md")

    write_csv(rows, full_csv_path)
    write_csv([r for r in rows if r["STATUS"] == "FAIL"], fail_csv_path)
    write_summary_md(rows, summary_md_path, prowler_csv)

    print("Done. Files written:")
    print(f"  - {full_csv_path}")
    print(f"  - {fail_csv_path}")
    print(f"  - {summary_md_path}")


if __name__ == "__main__":
    main()
