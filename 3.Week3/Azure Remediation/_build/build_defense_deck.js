const pptxgen = require("pptxgenjs");

// ---- Palette: "Midnight Executive" - fits a cloud-security capstone defense ----
const NAVY = "1E2761";
const ICE = "CADCFC";
const WHITE = "FFFFFF";
const SLATE = "44506B";
const TEXT_DARK = "1C2333";
const TEXT_MUTED = "5B6B8C";
const ACCENT = "3D8BFF";

const FONT_HEAD = "Cambria";
const FONT_BODY = "Calibri";

function newDeck() {
  const p = new pptxgen();
  p.layout = "LAYOUT_WIDE"; // 13.3 x 7.5 in
  return p;
}

function darkSlide(p) {
  const s = p.addSlide();
  s.background = { color: NAVY };
  return s;
}
function lightSlide(p) {
  const s = p.addSlide();
  s.background = { color: WHITE };
  return s;
}

function badge(slide, x, y, num, size = 0.45) {
  slide.addShape("ellipse", { x, y, w: size, h: size, fill: { color: ACCENT }, line: { type: "none" } });
  slide.addText(String(num), {
    x, y, w: size, h: size, align: "center", valign: "middle",
    fontFace: FONT_BODY, fontSize: 16, bold: true, color: WHITE, margin: 0,
  });
}

function title(slide, text, opts = {}) {
  slide.addText(text, {
    x: 0.6, y: 0.45, w: 12.1, h: 0.9, fontFace: FONT_HEAD, fontSize: 32, bold: true,
    color: opts.dark ? WHITE : NAVY, margin: 0,
  });
}

function footer(slide, n, dark = false) {
  slide.addText("CloudGuardian - Week 3: Remediate & Govern", {
    x: 0.6, y: 7.12, w: 8, h: 0.3, fontFace: FONT_BODY, fontSize: 9,
    color: dark ? "8C9BC4" : TEXT_MUTED, margin: 0,
  });
  slide.addText(String(n), {
    x: 12.4, y: 7.12, w: 0.4, h: 0.3, fontFace: FONT_BODY, fontSize: 9, align: "right",
    color: dark ? "8C9BC4" : TEXT_MUTED, margin: 0,
  });
}

const pptx = newDeck();

// ============================================================
// Slide 1 - Title
// ============================================================
{
  const s = darkSlide(pptx);
  s.addShape("rect", { x: 0, y: 0, w: 4.6, h: 7.5, fill: { color: "17204A" }, line: { type: "none" } });
  s.addShape("ellipse", { x: -1.4, y: 5.1, w: 4, h: 4, fill: { color: "27306B" }, line: { type: "none" } });
  s.addShape("ellipse", { x: -0.6, y: -1.6, w: 2.6, h: 2.6, fill: { color: "27306B" }, line: { type: "none" } });

  s.addText("CloudGuardian", { x: 5.0, y: 2.15, w: 7.7, h: 1.0, fontFace: FONT_HEAD, fontSize: 46, bold: true, color: WHITE, margin: 0 });
  s.addText("Week 3 - Remediate and Govern", { x: 5.0, y: 3.05, w: 7.7, h: 0.6, fontFace: FONT_BODY, fontSize: 22, color: ICE, margin: 0 });
  s.addShape("line", { x: 5.02, y: 3.75, w: 0, h: 0.9, line: { color: ACCENT, width: 2 } });
  s.addText([
    { text: "IIT Roorkee - PG Certificate in AI Powered Cybersecurity\n", options: { fontSize: 15, color: "AEB9DC" } },
    { text: "Capstone Project - Microsoft Azure Track\n", options: { fontSize: 15, color: "AEB9DC" } },
    { text: "Kedar Pavaskar", options: { fontSize: 15, bold: true, color: WHITE } },
  ], { x: 5.25, y: 3.85, w: 7, h: 1.2, fontFace: FONT_BODY, lineSpacing: 24, margin: 0 });
}

// ============================================================
// Slide 2 - Recap Weeks 1 & 2
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Where We Left Off");
  s.addText("Two weeks of foundation this week's automation depends on", { x: 0.6, y: 1.15, w: 11, h: 0.4, fontFace: FONT_BODY, fontSize: 14, italic: true, color: TEXT_MUTED, margin: 0 });

  const cards = [
    ["W1", "Build & Break", "3-tier Azure workload via Terraform, 16 deliberate misconfigurations across IAM, storage, networking, encryption, logging."],
    ["W2", "Detect & Prioritize", "3 CSPM tools cross-referenced into one findings schema; CVSS x Exposure x Blast-Radius risk scoring; LLM explanations verified against raw scanner data."],
    ["W3", "Remediate & Govern", "Today: safe automated fixes, human approval gate, continuous drift detection, privacy-preserving LLM calls, full compliance crosswalk."],
  ];
  const cardW = 3.86, gap = 0.28, startX = 0.6, y = 2.0, h = 4.6;
  cards.forEach((c, i) => {
    const x = startX + i * (cardW + gap);
    const fill = i === 2 ? NAVY : "F2F5FA";
    const textColor = i === 2 ? WHITE : TEXT_DARK;
    const mutedColor = i === 2 ? "C7D2EE" : TEXT_MUTED;
    s.addShape("roundRect", { x, y, w: cardW, h, rectRadius: 0.12, fill: { color: fill }, line: { type: "none" }, shadow: i === 2 ? undefined : { type: "outer", color: "9AA6C4", opacity: 0.35, blur: 6, offset: 3, angle: 90 } });
    badge(s, x + 0.35, y + 0.35, i + 1);
    s.addText(c[1], { x: x + 0.3, y: y + 1.0, w: cardW - 0.6, h: 0.6, fontFace: FONT_HEAD, fontSize: 18, bold: true, color: textColor, margin: 0 });
    s.addText(c[2], { x: x + 0.3, y: y + 1.65, w: cardW - 0.6, h: h - 2.0, fontFace: FONT_BODY, fontSize: 12.5, color: mutedColor, margin: 0, valign: "top", lineSpacingMultiple: 1.15 });
  });
  footer(s, 2);
}

// ============================================================
// Slide 3 - Week 3 objectives
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Week 3 Objectives");
  const items = [
    ["Automate safely", "Fix 6 well-understood, reversible controls without a human touching a keyboard - for low-risk findings only."],
    ["Gate on approval", "High/Critical findings require an explicit human Approve before anything changes."],
    ["Govern, not just fix", "Re-verify daily that a remediated control hasn't silently drifted back."],
    ["Protect privacy in the loop", "Tokenize identifying data before any LLM call; hard-block the call if anything leaks."],
    ["Prove compliance", "Map every control to ISO 27001 Annex A, Microsoft Cloud Security Benchmark, and DPDP Act 2023."],
  ];
  let y = 1.5;
  items.forEach((it, i) => {
    badge(s, 0.7, y, i + 1, 0.5);
    s.addText(it[0], { x: 1.5, y: y - 0.05, w: 3.6, h: 0.6, fontFace: FONT_HEAD, fontSize: 16, bold: true, color: NAVY, margin: 0, valign: "middle" });
    s.addText(it[1], { x: 5.2, y: y - 0.05, w: 7.3, h: 0.65, fontFace: FONT_BODY, fontSize: 13, color: TEXT_DARK, margin: 0, valign: "middle" });
    if (i < items.length - 1) s.addShape("line", { x: 0.7, y: y + 0.72, w: 11.9, h: 0, line: { color: "E3E7F2", width: 1 } });
    y += 1.0;
  });
  footer(s, 3);
}

// ============================================================
// Slide 4 - Architecture diagram
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Event-Driven Remediation Architecture");

  const boxH = 0.85, y1 = 2.05, yTop = y1 - 0.68, yBot = y1 + 0.68, y2 = 4.35;
  function box(x, y, w, label, sub, fill, textColor = WHITE) {
    s.addShape("roundRect", { x, y, w, h: boxH, rectRadius: 0.08, fill: { color: fill }, line: { type: "none" } });
    s.addText(label, { x: x + 0.1, y: y + 0.06, w: w - 0.2, h: 0.38, fontFace: FONT_BODY, fontSize: 12, bold: true, color: textColor, margin: 0, align: "center" });
    s.addText(sub, { x: x + 0.1, y: y + 0.44, w: w - 0.2, h: 0.38, fontFace: FONT_BODY, fontSize: 9, color: textColor, margin: 0, align: "center" });
  }
  function arrow(x1, y1_, x2, y2_) {
    s.addShape("line", { x: x1, y: y1_, w: x2 - x1, h: y2_ - y1_, line: { color: SLATE, width: 1.75, endArrowType: "triangle" } });
  }

  box(0.6, y1, 2.3, "CSPM Findings", "Week 2 pipeline", SLATE);
  box(3.3, y1, 2.5, "Event Grid Topic", "evgt-cloudguardian-findings", NAVY);
  arrow(2.9, y1 + boxH / 2, 3.3, y1 + boxH / 2);

  box(6.4, yTop, 2.7, "Low / Medium severity", "advanced filter: data.severity", "E3E7F2", TEXT_DARK);
  box(6.4, yBot, 2.7, "High / Critical severity", "advanced filter: data.severity", "E3E7F2", TEXT_DARK);
  arrow(5.8, y1 + boxH / 2, 6.4, yTop + boxH / 2);
  arrow(5.8, y1 + boxH / 2, 6.4, yBot + boxH / 2);

  box(9.7, yTop, 3.0, "Function App", "auto_remediate (Event Grid trigger)", ACCENT);
  arrow(9.1, yTop + boxH / 2, 9.7, yTop + boxH / 2);

  box(9.7, yBot, 3.0, "Logic App", "human approval (ACS Email)", "6E4EBE");
  arrow(9.1, yBot + boxH / 2, 9.7, yBot + boxH / 2);

  box(9.7, y2, 3.0, "Function App", "execute-remediation (HTTP, post-approval)", ACCENT);
  arrow(11.2, yBot + boxH, 11.2, y2);

  box(6.4, y2, 2.7, "6 Remediation Modules", "shared dispatcher", "E3E7F2", TEXT_DARK);
  arrow(9.7, y2 + boxH / 2, 9.1, y2 + boxH / 2);

  box(3.3, y2, 2.5, "Target Azure Resources", "Storage / SQL / Key Vault", SLATE);
  arrow(6.4, y2 + boxH / 2, 5.8, y2 + boxH / 2);

  box(0.6, y2, 2.3, "Log Analytics", "audit trail (KQL)", "17204A");
  arrow(3.3, y2 + boxH / 2, 2.9, y2 + boxH / 2);

  s.addText("Automation Account (daily): re-checks all 6 controls, flags drift without silently re-fixing", {
    x: 0.6, y: 5.55, w: 12.1, h: 0.5, fontFace: FONT_BODY, fontSize: 12, italic: true, color: TEXT_MUTED, align: "center", margin: 0,
  });
  footer(s, 4);
}

// ============================================================
// Slide 5 - The 6 remediation controls (table)
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Six Safe, Idempotent, Reversible Fixes");
  const rows = [
    [{ text: "Control", options: { bold: true, color: WHITE, fill: NAVY } }, { text: "Fix", options: { bold: true, color: WHITE, fill: NAVY } }, { text: "CIS / MCSB", options: { bold: true, color: WHITE, fill: NAVY } }],
    ["storage_public_access", "Disable account-level anonymous blob access", "CIS 3.6 / MCSB DP-2, NS-2"],
    ["storage_encryption", "Enforce HTTPS-only + TLS 1.2 minimum", "CIS 3.1, 3.12 / MCSB DP-3, DP-4"],
    ["diagnostic_logging", "Re-attach diagnostics to Log Analytics", "CIS 5.1.x / MCSB LT-3, LT-4"],
    ["sql_encryption", "Enable Transparent Data Encryption", "CIS 4.1.1 / MCSB DP-4"],
    ["keyvault_firewall", "Network ACL default action -> Deny", "MCSB NS-2, DP-8"],
    ["tagging", "Merge required governance tags", "MCSB GS-1"],
  ].map((r, i) => i === 0 ? r : r.map((c) => ({ text: c, options: { color: TEXT_DARK, fill: i % 2 === 0 ? "F2F5FA" : WHITE } })));

  s.addTable(rows, {
    x: 0.6, y: 1.5, w: 12.1, colW: [3.6, 5.5, 3.0],
    fontFace: FONT_BODY, fontSize: 12, border: { type: "solid", color: "E3E7F2", pt: 1 },
    autoPage: false, rowH: 0.55, valign: "middle",
  });
  s.addText("All 6 are boolean/property toggles - no destructive operations, all idempotent, all reversible.", {
    x: 0.6, y: 5.7, w: 12.1, h: 0.4, fontFace: FONT_BODY, fontSize: 12, italic: true, color: TEXT_MUTED, margin: 0,
  });
  footer(s, 5);
}

// ============================================================
// Slide 6 - Human approval workflow
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "The Human Approval Gate");
  const steps = [
    ["Event Grid", "publishes a High/Critical finding to the Logic App"],
    ["Logic App", "forwards to the Function App, which emails the approver Approve/Reject links via Azure Communication Services"],
    ["Human", "reviews finding, severity, resource, proposed fix - clicks Approve or Reject"],
    ["Approve", "the link click hits the Function's approval_decision endpoint directly - remediation executes"],
    ["Reject / no action", "resource is left untouched; the decision itself is the audit record"],
  ];
  const w = 2.28, gap = 0.14, y = 2.6, h = 1.9;
  steps.forEach((st, i) => {
    const x = 0.6 + i * (w + gap);
    const fill = i === 3 ? ACCENT : (i === 4 ? "B8324A" : NAVY);
    s.addShape("roundRect", { x, y, w, h, rectRadius: 0.1, fill: { color: fill }, line: { type: "none" } });
    s.addText(st[0], { x: x + 0.15, y: y + 0.18, w: w - 0.3, h: 0.5, fontFace: FONT_HEAD, fontSize: 14, bold: true, color: WHITE, margin: 0 });
    s.addText(st[1], { x: x + 0.15, y: y + 0.68, w: w - 0.3, h: h - 0.8, fontFace: FONT_BODY, fontSize: 10.5, color: "E3E7F2", margin: 0, valign: "top" });
    if (i < 3) s.addShape("line", { x: x + w, y: y + h / 2, w: gap, h: 0, line: { color: SLATE, width: 1.75, endArrowType: "triangle" } });
  });
  s.addText("Approving does not just log a decision - it is the ONLY thing that authorizes the Function to make a live change.", {
    x: 0.6, y: 5.0, w: 12.1, h: 0.6, fontFace: FONT_BODY, fontSize: 13, italic: true, color: TEXT_MUTED, align: "center", margin: 0,
  });
  footer(s, 6);
}

// ============================================================
// Slide 7 - Governance / drift detection
// ============================================================
{
  const s = darkSlide(pptx);
  title(s, "Governance: Remediation Isn't a One-Time Fix", { dark: true });
  s.addShape("roundRect", { x: 0.6, y: 1.7, w: 5.6, h: 4.6, rectRadius: 0.1, fill: { color: "27306B" }, line: { type: "none" } });
  s.addText("Daily", { x: 0.9, y: 2.0, w: 5, h: 0.9, fontFace: FONT_HEAD, fontSize: 44, bold: true, color: ACCENT, margin: 0 });
  s.addText("Automation Account runbook re-checks all 6 controls", { x: 0.9, y: 2.9, w: 5, h: 0.6, fontFace: FONT_BODY, fontSize: 15, color: WHITE, margin: 0 });
  s.addText("Test-RemediationDrift.ps1 runs as the Automation Account's own Managed Identity - same read-only calls an auditor would make.", {
    x: 0.9, y: 3.6, w: 5, h: 1.0, fontFace: FONT_BODY, fontSize: 12, color: "AEB9DC", margin: 0,
  });
  s.addShape("line", { x: 0.9, y: 4.8, w: 5, h: 0, line: { color: "3D4A80", width: 1 } });
  s.addText("Flags drift. Does NOT silently re-fix it.", { x: 0.9, y: 4.95, w: 5, h: 0.5, fontFace: FONT_BODY, fontSize: 13, bold: true, color: "F2C94C", margin: 0 });
  s.addText("Drift is a signal a human should look at - was it accidental, or a deliberate, approved exception?", {
    x: 0.9, y: 5.45, w: 5, h: 0.7, fontFace: FONT_BODY, fontSize: 12, italic: true, color: "AEB9DC", margin: 0,
  });

  const checks = ["Storage public access", "Storage HTTPS/TLS", "Diagnostic logging", "SQL TDE", "Key Vault firewall", "Required tags"];
  let cy = 1.9;
  checks.forEach((c) => {
    s.addShape("ellipse", { x: 6.7, y: cy + 0.06, w: 0.16, h: 0.16, fill: { color: ACCENT }, line: { type: "none" } });
    s.addText(c, { x: 7.0, y: cy - 0.08, w: 5.5, h: 0.45, fontFace: FONT_BODY, fontSize: 14, color: WHITE, margin: 0 });
    cy += 0.72;
  });
  footer(s, 7, true);
}

// ============================================================
// Slide 8 - Privacy-preserving LLM pipeline
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Privacy-Preserving LLM Pipeline");
  const stages = [
    ["1. Tokenize", "subscription_id, object_id, upn, resource_name, principal_name -> deterministic tokens", "E3E7F2", TEXT_DARK],
    ["2. Verify", "regex guardrail re-scans the FINAL outbound payload; raises PrivacyLeakError and BLOCKS the call on any match", "B8324A", WHITE],
    ["3. Call LLM", "only tokens (RESOURCE_1, UPN_1...) ever leave the Azure boundary", ACCENT, WHITE],
    ["4. Detokenize", "real values restored only after the response returns, inside Azure", "E3E7F2", TEXT_DARK],
  ];
  const w = 2.85, gap = 0.15, y = 2.2, h = 2.3;
  stages.forEach((st, i) => {
    const x = 0.6 + i * (w + gap);
    s.addShape("roundRect", { x, y, w, h, rectRadius: 0.1, fill: { color: st[2] }, line: { type: "none" } });
    s.addText(st[0], { x: x + 0.18, y: y + 0.2, w: w - 0.36, h: 0.5, fontFace: FONT_HEAD, fontSize: 15, bold: true, color: st[3], margin: 0 });
    s.addText(st[1], { x: x + 0.18, y: y + 0.75, w: w - 0.36, h: h - 0.95, fontFace: FONT_BODY, fontSize: 11, color: st[3], margin: 0, valign: "top" });
    if (i < 3) s.addShape("line", { x: x + w, y: y + h / 2, w: gap, h: 0, line: { color: SLATE, width: 1.75, endArrowType: "triangle" } });
  });
  s.addShape("roundRect", { x: 0.6, y: 4.95, w: 12.1, h: 1.35, rectRadius: 0.08, fill: { color: NAVY }, line: { type: "none" } });
  s.addText([
    { text: "DPDP Rules, 2025: ", options: { bold: true, color: ACCENT } },
    { text: "reasonable security safeguards include “encryption, obfuscation, masking, or the use of virtual tokens mapped to specific personal data.” This pipeline implements that safeguard literally, for UPNs and tenant identifiers.", options: { color: "E3E7F2" } },
  ], { x: 0.9, y: 5.1, w: 11.5, h: 1.1, fontFace: FONT_BODY, fontSize: 13, margin: 0, valign: "middle", lineSpacingMultiple: 1.2 });
  footer(s, 8);
}

// ============================================================
// Slide 9 - Compliance mapping summary
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Compliance Crosswalk at a Glance");
  const stats = [
    ["10", "controls mapped\nend to end"],
    ["12+", "ISO/IEC 27001:2022\nAnnex A references"],
    ["1", "Microsoft Cloud Security\nBenchmark (v1, GA)"],
    ["2025", "DPDP Rules notified\n(14 Nov 2025)"],
  ];
  const w = 2.85, gap = 0.2, y = 1.7;
  stats.forEach((st, i) => {
    const x = 0.6 + i * (w + gap);
    s.addShape("roundRect", { x, y, w, h: 2.1, rectRadius: 0.1, fill: { color: "F2F5FA" }, line: { type: "none" } });
    s.addText(st[0], { x, y: y + 0.25, w, h: 1.0, fontFace: FONT_HEAD, fontSize: 42, bold: true, color: NAVY, align: "center", margin: 0 });
    s.addText(st[1], { x: x + 0.15, y: y + 1.3, w: w - 0.3, h: 0.7, fontFace: FONT_BODY, fontSize: 11.5, color: TEXT_MUTED, align: "center", margin: 0 });
  });
  s.addText("Full row-by-row mapping: Week3_Compliance_Crosswalk.xlsx", {
    x: 0.6, y: 4.05, w: 12.1, h: 0.4, fontFace: FONT_BODY, fontSize: 12, italic: true, color: TEXT_MUTED, margin: 0,
  });
  s.addText("DPDP Act 2023 status - stated accurately, not oversold", {
    x: 0.6, y: 4.65, w: 12.1, h: 0.4, fontFace: FONT_HEAD, fontSize: 15, bold: true, color: NAVY, margin: 0,
  });
  s.addText([
    { text: "Rules notified 14 Nov 2025. ", options: { bold: true } },
    { text: "Data Protection Board instituted immediately. Consent Manager registration from Nov 2026. ", options: {} },
    { text: "Main compliance duties - security safeguards, breach notification - become mandatory 13 May 2027.", options: { bold: true } },
  ], { x: 0.6, y: 5.1, w: 12.1, h: 1.2, fontFace: FONT_BODY, fontSize: 13, color: TEXT_DARK, margin: 0, lineSpacingMultiple: 1.3 });
  s.addText("CloudGuardian's privacy pipeline is built ahead of the mandatory date, not because it is currently required.", {
    x: 0.6, y: 6.35, w: 12.1, h: 0.5, fontFace: FONT_BODY, fontSize: 12, italic: true, color: TEXT_MUTED, margin: 0,
  });
  footer(s, 9);
}

// ============================================================
// Slide 10 - Security design decisions
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Security Design Decisions");
  const decisions = [
    ["Zero Trust", "System-Assigned Managed Identity only - no stored secret, no service principal password anywhere in this stack."],
    ["Least privilege", "A custom RBAC role scoped to exactly the actions 6 remediations need - not built-in Contributor."],
    ["Defense in depth", "Key Vault firewall changes are approval-gated even at low severity - the one control that could break a legitimate caller."],
    ["Auditable by default", "Every remediation, approval, and drift check is independently logged and queryable via KQL."],
  ];
  const w = 5.85, gap = 0.4, colY = [1.6, 3.85];
  decisions.forEach((d, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.6 + col * (w + gap);
    const y = colY[row];
    s.addShape("roundRect", { x, y, w, h: 2.05, rectRadius: 0.1, fill: { color: row === 0 && col === 0 ? NAVY : "F2F5FA" }, line: { type: "none" } });
    const dark = row === 0 && col === 0;
    s.addText(d[0], { x: x + 0.3, y: y + 0.25, w: w - 0.6, h: 0.5, fontFace: FONT_HEAD, fontSize: 17, bold: true, color: dark ? WHITE : NAVY, margin: 0 });
    s.addText(d[1], { x: x + 0.3, y: y + 0.8, w: w - 0.6, h: 1.1, fontFace: FONT_BODY, fontSize: 12.5, color: dark ? "C7D2EE" : TEXT_DARK, margin: 0, valign: "top", lineSpacingMultiple: 1.2 });
  });
  footer(s, 10);
}

// ============================================================
// Slide 11 - Live demo flow
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Live Demo - What You're About to See");
  const steps = [
    "Toggle a real misconfiguration by hand (Storage public access)",
    "Publish the finding to Event Grid (curl - simulates Week 2's pipeline)",
    "Medium severity -> auto-remediates in seconds, no human involved",
    "High severity (SQL encryption) -> approval email arrives -> Approve -> Function executes",
    "Query Log Analytics live: one KQL query shows both remediations in the audit trail",
  ];
  let y = 1.7;
  steps.forEach((st, i) => {
    badge(s, 0.7, y, i + 1, 0.5);
    s.addShape("roundRect", { x: 1.5, y: y - 0.15, w: 11.0, h: 0.8, rectRadius: 0.08, fill: { color: i % 2 === 0 ? "F2F5FA" : WHITE }, line: { type: "none" } });
    s.addText(st, { x: 1.75, y: y - 0.15, w: 10.5, h: 0.8, fontFace: FONT_BODY, fontSize: 14, color: TEXT_DARK, margin: 0, valign: "middle" });
    y += 1.0;
  });
  footer(s, 11);
}

// ============================================================
// Slide 12 - Challenges & lessons learned
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Challenges & Lessons Learned");
  const items = [
    ["An M365 mailbox would have blocked the lab", "The original approval design used the Office 365 Outlook connector's Send-email action, which needs a real Microsoft 365 mailbox and a manual OAuth click. Redesigned around Azure Communication Services Email (Managed Identity auth) with the Function App handling the Approve/Reject branch - removed the M365 dependency AND the azapi provider it also required, simplifying the stack as a side effect."],
    ["Azure SDK vs. Portal terminology drift", "TDE is an attribute on the database, not a separate resource - consistent with what Week 1 already taught about azurerm_mssql_database_transparent_data_encryption not existing."],
    ["A privacy bug caught by testing, not review", "An early tokenizer regex missed hyphen-less storage account names in free text - fixed by tokenizing known structured values as exact literals first, regex only as a last-resort net."],
    ["Windows tooling friction (Week 1 carryover)", "Prowler's MAX_PATH limit, PowerShell COM [ref] marshalling - same discipline of diagnose-and-fix-sequentially applied again this week."],
  ];
  let y = 1.6;
  items.forEach((it) => {
    s.addShape("roundRect", { x: 0.6, y, w: 12.1, h: 1.15, rectRadius: 0.08, fill: { color: "F2F5FA" }, line: { type: "none" } });
    s.addText(it[0], { x: 0.9, y: y + 0.1, w: 11.5, h: 0.4, fontFace: FONT_HEAD, fontSize: 14, bold: true, color: NAVY, margin: 0 });
    s.addText(it[1], { x: 0.9, y: y + 0.5, w: 11.5, h: 0.6, fontFace: FONT_BODY, fontSize: 11.5, color: TEXT_DARK, margin: 0, valign: "top" });
    y += 1.3;
  });
  footer(s, 12);
}

// ============================================================
// Slide 13 - Results & future work
// ============================================================
{
  const s = lightSlide(pptx);
  title(s, "Results & What's Next");
  s.addText("Delivered this week", { x: 0.6, y: 1.5, w: 5.8, h: 0.4, fontFace: FONT_HEAD, fontSize: 16, bold: true, color: NAVY, margin: 0 });
  const done = ["6 remediation functions, idempotent & dry-run capable", "Event-driven routing by severity (Event Grid)", "Human approval gate (Logic App + ACS Email)", "Daily drift-detection governance runbook", "Privacy-preserving, leakage-guarded LLM pipeline", "Full ISO 27001 / MCSB / DPDP crosswalk"];
  let y = 2.0;
  done.forEach((d) => {
    s.addShape("ellipse", { x: 0.65, y: y + 0.07, w: 0.14, h: 0.14, fill: { color: ACCENT }, line: { type: "none" } });
    s.addText(d, { x: 0.95, y: y - 0.08, w: 5.4, h: 0.45, fontFace: FONT_BODY, fontSize: 12, color: TEXT_DARK, margin: 0 });
    y += 0.55;
  });

  s.addText("Next", { x: 6.9, y: 1.5, w: 5.8, h: 0.4, fontFace: FONT_HEAD, fontSize: 16, bold: true, color: NAVY, margin: 0 });
  const next = ["Wire the existing Streamlit dashboard to live Function/Logic App status", "Extend the drift runbook to open a tracked ticket automatically", "Grow from 6 to the full misconfiguration catalogue", "Move Key Vault access from function keys to Azure AD Easy Auth"];
  y = 2.0;
  next.forEach((d) => {
    s.addShape("ellipse", { x: 6.95, y: y + 0.07, w: 0.14, h: 0.14, fill: { color: "6E4EBE" }, line: { type: "none" } });
    s.addText(d, { x: 7.25, y: y - 0.08, w: 5.4, h: 0.6, fontFace: FONT_BODY, fontSize: 12, color: TEXT_DARK, margin: 0 });
    y += 0.75;
  });
  footer(s, 13);
}

// ============================================================
// Slide 14 - Thank you / Q&A
// ============================================================
{
  const s = darkSlide(pptx);
  s.addShape("ellipse", { x: 9.8, y: -1.5, w: 5, h: 5, fill: { color: "27306B" }, line: { type: "none" } });
  s.addText("Thank you", { x: 0.9, y: 2.7, w: 10, h: 1.0, fontFace: FONT_HEAD, fontSize: 44, bold: true, color: WHITE, margin: 0 });
  s.addText("Questions?", { x: 0.9, y: 3.6, w: 10, h: 0.7, fontFace: FONT_BODY, fontSize: 22, color: ICE, margin: 0 });
  s.addText("Kedar Pavaskar  |  CloudGuardian  |  IIT Roorkee PG Certificate in AI Powered Cybersecurity", {
    x: 0.9, y: 6.6, w: 11, h: 0.5, fontFace: FONT_BODY, fontSize: 12, color: "AEB9DC", margin: 0,
  });
}

pptx.writeFile({ fileName: "../docs/Week3_Defense_Presentation.pptx" }).then(() => console.log("wrote Week3_Defense_Presentation.pptx"));
