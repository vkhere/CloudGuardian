# Catalogue — hand-maintained reference data

These three files are **not** scanner output. They are the reference data that
lets the console answer questions the scanners cannot. All three are optional;
a missing file just makes the relevant page show an explanation instead.

Regenerate the worked examples any time with:

```
python tools/generate_catalogue.py
```

## toggles.csv — your deliberate misconfigurations

Drives the **Detection coverage** page.

| Column | Meaning |
| --- | --- |
| `toggle_id` | Your reference, e.g. `AZ-T01` |
| `cloud` | Azure / AWS |
| `toggle_name` | The Terraform variable, or `(no toggle)` for a retained baseline gap |
| `category` | Identity / Storage / Networking / Logging / Encryption / Monitoring |
| `expected_finding` | The `finding_id` the scanners should raise. **This is the join key** |
| `severity` | Critical / High / Medium / Low |
| `rationale` | Why you introduced it — goes into your Week 1 report |
| `revert` | Exactly how to put it back |

Coverage is measured against the **After misconfig** scan, because that is when
every toggle was switched on.

## attack_paths.csv — blast radius chains

Drives the **Attack paths** page. One row per step; rows sharing a `path_id`
form one chain, ordered by `step_order`.

| Column | Meaning |
| --- | --- |
| `path_id` | e.g. `AP-01` |
| `path_name` | Human name of the chain |
| `cloud`, `severity` | Same on every row of the path |
| `step_order` | 1, 2, 3 … |
| `node_label` | Text shown on the graph node |
| `node_type` | `entry`, `pivot` or `target` — controls the node colour |
| `finding_id` | The finding that enables this step. Blank means a context node |
| `note` | What the attacker does at this step |

A path is shown as **Live** only when every step that references a finding is
still failing. Remediate any one step and the chain breaks.

## dpdp_map.csv — ISO 27001 to DPDP Act 2023

Drives the DPDP column of the **Compliance crosswalk** tab.

| Column | Meaning |
| --- | --- |
| `iso_27001` | Must match the `iso_27001` value in your findings exactly |
| `dpdp_section` | e.g. `S.8(5)` |
| `dpdp_obligation` | The obligation in plain words |

The DPDP Act does not enumerate technical controls, so this mapping is an
argued link between each control and a statutory obligation. Present it as
your reasoning, not as a certified mapping.
