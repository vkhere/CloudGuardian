"""
CloudGuardian - Compliance Crosswalk Generator
------------------------------------------------
Upload your Week 2/3 consolidated CSPM findings (CSV/Excel), pick any 2-3
security frameworks, and this app auto-matches every finding to the closest
control in each framework using TF-IDF + cosine similarity.

Run with:  streamlit run crosswalk_app.py
"""

import io
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

st.set_page_config(page_title="CloudGuardian Crosswalk", layout="wide")

# ----------------------------------------------------------------------
# 1. Built-in control knowledge base for each framework
#    (Trim/extend these lists any time - each control needs: id, title, text)
# ----------------------------------------------------------------------

FRAMEWORKS = {
    "ISO 27001:2022": [
        ("A.5.15", "Access control", "Rules to control physical and logical access to information and assets based on business requirements."),
        ("A.5.16", "Identity management", "Full life cycle management of identities used to grant access to systems and services."),
        ("A.5.17", "Authentication information", "Allocation and management of authentication information such as passwords and keys."),
        ("A.5.18", "Access rights", "Access rights to information and assets are provisioned, reviewed, modified and removed."),
        ("A.8.2", "Privileged access rights", "Allocation and use of privileged access rights are restricted and managed, including admin and root accounts."),
        ("A.8.3", "Information access restriction", "Access to information and application system functions is restricted per the access control policy."),
        ("A.8.5", "Secure authentication", "Secure authentication technologies and procedures based on information access restrictions."),
        ("A.8.9", "Configuration management", "Configurations, including security configurations of hardware, software and networks, are established, documented, monitored and reviewed."),
        ("A.8.10", "Information deletion", "Information stored in systems is deleted when no longer required."),
        ("A.8.12", "Data leakage prevention", "Measures applied to systems, networks and devices that process, store or transmit sensitive information to prevent data leakage."),
        ("A.8.13", "Information backup", "Backup copies of information, software and systems are maintained and regularly tested."),
        ("A.8.15", "Logging", "Logs recording activities, exceptions, faults and events are produced, retained and reviewed."),
        ("A.8.16", "Monitoring activities", "Networks, systems and applications are monitored for anomalous behaviour and potential incidents."),
        ("A.8.20", "Networks security", "Networks and network devices are secured, managed and controlled to protect information in systems and applications, preventing resources such as databases, storage and management ports from being unnecessarily exposed or publicly accessible over the internet."),
        ("A.8.24", "Use of cryptography", "Rules for effective use of cryptography, including encryption of data at rest and in transit."),
        ("A.8.28", "Secure coding", "Secure coding principles are applied to software development to reduce security vulnerabilities."),
    ],
    "HIPAA Security Rule": [
        ("164.308(a)(1)", "Security Management Process", "Implement policies to prevent, detect, contain and correct security violations, including risk analysis and risk management."),
        ("164.308(a)(3)", "Workforce Security", "Ensure workforce members have appropriate access to electronic protected health information and prevent unauthorized access."),
        ("164.308(a)(4)", "Information Access Management", "Implement policies for authorizing access to electronic protected health information consistent with least privilege."),
        ("164.308(a)(5)", "Security Awareness and Training", "Implement a security awareness and training program for all workforce members, including management of passwords."),
        ("164.308(a)(6)", "Security Incident Procedures", "Implement policies to address, identify, respond to, and document security incidents and their outcomes."),
        ("164.308(a)(7)", "Contingency Plan", "Establish policies for responding to an emergency, including data backup, disaster recovery, and emergency mode operation."),
        ("164.310(d)(1)", "Device and Media Controls", "Implement policies governing receipt and removal of hardware and media containing electronic protected health information."),
        ("164.312(a)(1)", "Access Control", "Implement technical policies to allow access only to persons or software programs that have been granted access rights, including unique user identification."),
        ("164.312(a)(2)(iv)", "Encryption and Decryption", "Implement a mechanism to encrypt and decrypt electronic protected health information at rest."),
        ("164.312(b)", "Audit Controls", "Implement hardware, software, and procedural mechanisms that record and examine activity in systems containing electronic protected health information."),
        ("164.312(c)(1)", "Integrity", "Implement policies to protect electronic protected health information from improper alteration or destruction."),
        ("164.312(d)", "Person or Entity Authentication", "Implement procedures to verify that a person or entity seeking access is the one claimed."),
        ("164.312(e)(1)", "Transmission Security", "Implement technical security measures to guard against unauthorized access to information transmitted over a network, including encryption in transit and preventing databases from being publicly accessible over the internet."),
    ],
    "CIS Controls v8": [
        ("CIS 3.3", "Configure Data Access Control Lists", "Configure data access control lists based on a user's need to know, applied at local and remote file systems, databases and applications."),
        ("CIS 3.10", "Encrypt Sensitive Data in Transit", "Encrypt sensitive data in transit using network-level encryption such as TLS."),
        ("CIS 3.11", "Encrypt Sensitive Data at Rest", "Encrypt sensitive data at rest on servers, applications and databases using appropriate encryption methods."),
        ("CIS 4.1", "Establish and Maintain a Secure Configuration Process", "Establish and maintain a secure configuration process for enterprise assets and software, including cloud services."),
        ("CIS 5.1", "Establish and Maintain an Inventory of Accounts", "Establish and maintain an inventory of all accounts managed in the enterprise, reviewed on a recurring basis."),
        ("CIS 5.4", "Restrict Administrator Privileges to Dedicated Admin Accounts", "Ensure administrative accounts are used only for administrative activities, not day-to-day access, and follow least privilege."),
        ("CIS 6.1", "Establish an Access Granting Process", "Establish and follow a documented process for granting access to enterprise assets upon new hire or role change."),
        ("CIS 6.2", "Establish an Access Revoking Process", "Establish and follow a process for revoking access to assets promptly when no longer required."),
        ("CIS 8.2", "Collect Audit Logs", "Collect audit logs, including detailed logs from cloud platforms and services, ensuring logging is enabled for all systems."),
        ("CIS 8.5", "Collect Detailed Audit Logs", "Configure detailed audit logging for enterprise assets to include event source, timestamp, and other relevant details."),
        ("CIS 11.1", "Establish and Maintain a Data Recovery Process", "Establish and maintain a documented data recovery process including automated backups."),
        ("CIS 12.2", "Establish and Maintain a Secure Network Architecture", "Design and maintain a secure network architecture including segmentation and restriction of unnecessary access such as open ports, publicly accessible databases and storage exposed to the internet."),
        ("CIS 13.1", "Centralize Security Event Alerting", "Centralize security event alerting across enterprise assets for log correlation and analysis."),
    ],
    "PCI-DSS v4.0": [
        ("Req 1.2", "Network security controls", "Network security controls are configured and maintained to restrict connections between untrusted networks and system components in the cardholder data environment."),
        ("Req 2.2", "Secure configurations", "System components are configured and managed securely, removing default accounts, unnecessary services and insecure configurations."),
        ("Req 3.5", "Encryption of stored data", "Primary account numbers and sensitive stored data are rendered unreadable using strong cryptography, both at rest and in cloud storage."),
        ("Req 4.2", "Encryption in transit", "Strong cryptography is used to safeguard cardholder data during transmission over open, public networks."),
        ("Req 6.2", "Secure software development", "Custom and bespoke software is developed securely, addressing common vulnerabilities and following secure coding practices."),
        ("Req 7.2", "Least privilege access", "Access to system components and data is restricted based on job function and business need to know, following least privilege."),
        ("Req 8.3", "Strong authentication", "Strong authentication for users and administrators is established and managed for all access to system components."),
        ("Req 10.2", "Audit logging", "Audit logs are implemented to support the detection of anomalies and suspicious activity across all system components."),
        ("Req 10.4", "Log review", "Audit logs are reviewed regularly to identify anomalies or suspicious activity in the cardholder data environment."),
        ("Req 11.3", "Vulnerability management", "Internal and external vulnerabilities, including publicly accessible services and misconfigurations, are identified and addressed regularly."),
        ("Req 12.10", "Incident response", "An incident response plan is implemented and ready to be activated in the event of a suspected or confirmed security incident."),
    ],
    "DPDP Act 2023": [
        ("Sec 8(4)", "Reasonable security safeguards", "Data Fiduciary shall implement appropriate technical and organisational measures, including encryption, access control and monitoring, to prevent personal data breach."),
        ("Sec 8(5)", "Data retention limitation", "Personal data shall be erased when the purpose for processing is no longer being served and retention is not required for legal compliance, unless preservation is mandated by law."),
        ("Sec 8(6)", "Breach notification", "Data Fiduciary shall notify the Data Protection Board of India and affected Data Principals in the event of a personal data breach, in the prescribed manner."),
        ("Sec 8(7)", "Grievance redressal", "Data Fiduciary shall establish an effective mechanism to redress the grievances of Data Principals within a specified timeframe."),
        ("Sec 8(1)", "Accuracy of data", "Data Fiduciary shall ensure the personal data processed is accurate, complete and consistent for the purpose of processing."),
        ("Sec 8(2)", "Purpose limitation", "Personal data shall be processed only for the purpose for which consent was given by the Data Principal, or as otherwise permitted by law."),
        ("Sec 8(3)", "Third-party data sharing safeguards", "Data Fiduciary shall ensure that personal data shared with a Data Processor is protected by contractual obligations equivalent to those under the Act."),
        ("Sec 5", "Notice and consent", "Data Fiduciary shall give notice and obtain free, specific and informed consent from the Data Principal before processing personal data, in clear and plain language."),
    ],
}

# ----------------------------------------------------------------------
# 2. Helper functions
# ----------------------------------------------------------------------

def load_findings(uploaded_file) -> pd.DataFrame:
    """Read an uploaded CSV or Excel file into a DataFrame."""
    if uploaded_file.name.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(uploaded_file)
    return pd.read_csv(uploaded_file)


def build_control_corpus(framework_name: str):
    """Return (ids, titles, texts) for a framework's controls."""
    rows = FRAMEWORKS[framework_name]
    ids = [r[0] for r in rows]
    titles = [r[1] for r in rows]
    texts = [f"{r[1]}. {r[2]}" for r in rows]
    return ids, titles, texts


def match_findings_to_framework(finding_texts: list, framework_name: str):
    """
    For each finding, find the closest control in the given framework using
    TF-IDF + cosine similarity. Returns lists of matched id, title, score.
    """
    control_ids, control_titles, control_texts = build_control_corpus(framework_name)

    # Fit TF-IDF on BOTH findings and controls together so vocabulary overlaps
    corpus = list(finding_texts) + control_texts
    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(corpus)

    n_findings = len(finding_texts)
    finding_vectors = tfidf_matrix[:n_findings]
    control_vectors = tfidf_matrix[n_findings:]

    sim_matrix = cosine_similarity(finding_vectors, control_vectors)  # shape (n_findings, n_controls)

    best_idx = np.argmax(sim_matrix, axis=1)
    best_scores = sim_matrix[np.arange(n_findings), best_idx]

    matched_ids = [control_ids[i] for i in best_idx]
    matched_titles = [control_titles[i] for i in best_idx]

    return matched_ids, matched_titles, best_scores


def confidence_label(score: float, threshold_med: float, threshold_high: float) -> str:
    if score >= threshold_high:
        return "High"
    if score >= threshold_med:
        return "Medium"
    return "Low - review manually"


def guess_column(columns, keywords, fallback):
    """Return the first column whose name contains any keyword, else fallback."""
    cols = list(columns)
    for kw in keywords:
        for c in cols:
            if kw in c.lower():
                return c
    return fallback


def framework_prefix(framework_name: str) -> str:
    return framework_name.split(":")[0].replace(" ", "_")


def build_crosswalk_view(
    working_df: pd.DataFrame,
    id_col: str,
    title_col: str,
    selected_frameworks: list,
    include_scores: bool,
) -> pd.DataFrame:
    """
    Build the crosswalk-first export: check_id + finding title lead the table,
    followed by every selected framework's matched Control_ID (and Control_Title,
    and optionally Similarity_Score / Confidence) - grouped by framework, in the
    order the frameworks were selected. No other original finding columns are
    included, so every row is purely "this finding <-> its match in each
    selected framework".
    """
    lead_cols = [id_col]
    if title_col != id_col:
        lead_cols.append(title_col)

    ordered_cols = list(lead_cols)
    for fw in selected_frameworks:
        prefix = framework_prefix(fw)
        ordered_cols.append(f"{prefix}_Control_ID")
        ordered_cols.append(f"{prefix}_Control_Title")
        if include_scores:
            ordered_cols.append(f"{prefix}_Similarity_Score")
            ordered_cols.append(f"{prefix}_Confidence")

    # Guard against any missing column (shouldn't happen, but keeps this robust)
    ordered_cols = [c for c in ordered_cols if c in working_df.columns]
    crosswalk_df = working_df[ordered_cols].copy()
    crosswalk_df = crosswalk_df.rename(columns={id_col: "check_id", title_col: "finding_title"})
    return crosswalk_df


# ----------------------------------------------------------------------
# 3. Streamlit UI
# ----------------------------------------------------------------------

st.title("CloudGuardian - Compliance Crosswalk Generator")
st.caption("Week 3 deliverable helper: maps consolidated findings to ISO 27001 / HIPAA / CIS controls using TF-IDF cosine similarity.")

with st.expander("How does the matching work? (click to read)"):
    st.markdown(
        """
        Each finding's description and each control's description are converted into
        **TF-IDF vectors** (numeric representations of which words matter most in each text).

        **Cosine similarity** then measures the angle between a finding's vector and every
        control's vector in that framework. A score near **1.0** means the wording overlaps
        strongly (good match); a score near **0** means almost no shared vocabulary.

        The app picks the **single best-matching control per framework**, per finding.
        Always spot-check "Low" confidence matches manually - this is a starting draft
        for your crosswalk table, not a certified mapping.

        **Limitation to know:** TF-IDF matches on literal shared words, not meaning. A finding
        like "S3 bucket versioning suspended" may score low against every control simply because
        none of the control text uses the word "versioning" - that's expected, not a bug. Low
        scores are exactly the cases you should map by hand.
        """
    )

st.subheader("Step 1 - Upload your consolidated findings")
uploaded_file = st.file_uploader(
    "Upload your Week 2/3 consolidated CSPM findings (CSV or Excel)",
    type=["csv", "xlsx", "xls"],
)

if uploaded_file is not None:
    try:
        df = load_findings(uploaded_file)
    except Exception as e:
        st.error(f"Could not read file: {e}")
        st.stop()

    st.success(f"Loaded {len(df)} rows, {len(df.columns)} columns.")
    st.dataframe(df.head(10), use_container_width=True)

    st.subheader("Step 2 - Which columns hold the Check ID, Finding Title, and Description?")
    st.caption("These three are used to match findings AND to build the crosswalk export - check_id + finding title lead every download, matched against each framework you select below.")

    col_id, col_title, col_desc = st.columns(3)

    with col_id:
        default_id_col = guess_column(df.columns, ["check_id", "checkid", "check id"], df.columns[0])
        id_col = st.selectbox(
            "Check ID column",
            options=list(df.columns),
            index=list(df.columns).index(default_id_col),
        )

    with col_title:
        default_title_col = guess_column(df.columns, ["title", "finding_name", "name"], df.columns[0])
        title_col = st.selectbox(
            "Finding title column",
            options=list(df.columns),
            index=list(df.columns).index(default_title_col),
        )

    with col_desc:
        # Try to auto-suggest a likely text column for matching (fuller text = better TF-IDF matches)
        likely_cols = [c for c in df.columns if any(
            key in c.lower() for key in ["status_detail", "description", "message", "finding", "detail"]
        )]
        default_col = likely_cols[0] if likely_cols else df.columns[0]

        text_col = st.selectbox(
            "Description column (used for TF-IDF matching)",
            options=list(df.columns),
            index=list(df.columns).index(default_col),
        )

    st.subheader("Step 3 - Select at least 3 frameworks")
    selected_frameworks = st.multiselect(
        "Choose frameworks (minimum 3)",
        options=list(FRAMEWORKS.keys()),
        default=["ISO 27001:2022", "HIPAA Security Rule", "CIS Controls v8"],
    )

    if len(selected_frameworks) < 3:
        st.warning(f"Select at least 3 frameworks to continue. Currently selected: {len(selected_frameworks)}.")

    st.subheader("Step 4 - Confidence thresholds (optional tuning)")
    col_a, col_b = st.columns(2)
    with col_a:
        threshold_med = st.slider("Medium-confidence threshold", 0.0, 1.0, 0.05, 0.01)
    with col_b:
        threshold_high = st.slider("High-confidence threshold", 0.0, 1.0, 0.15, 0.01)

    include_scores = st.checkbox(
        "Include Similarity Score & Confidence columns in the crosswalk export",
        value=False,
        help="Off by default: the crosswalk export leads with check_id + finding title, then only the "
             "matched Control_ID + Control_Title per framework. Turn this on if you also want the "
             "similarity score and confidence label for each match.",
    )

    if st.button("Generate Crosswalk", type="primary", disabled=(len(selected_frameworks) == 0)):
        with st.spinner("Computing TF-IDF vectors and cosine similarity..."):
            working_df = df.copy()
            finding_texts = working_df[text_col].fillna("").astype(str).tolist()

            for fw in selected_frameworks:
                ids, titles, scores = match_findings_to_framework(finding_texts, fw)
                prefix = framework_prefix(fw)
                working_df[f"{prefix}_Control_ID"] = ids
                working_df[f"{prefix}_Control_Title"] = titles
                working_df[f"{prefix}_Similarity_Score"] = np.round(scores, 3)
                working_df[f"{prefix}_Confidence"] = [
                    confidence_label(s, threshold_med, threshold_high) for s in scores
                ]

        st.success("Crosswalk generated.")

        # ------------------------------------------------------------------
        # Crosswalk-first view: check_id + finding title lead, followed by
        # each selected framework's matched Control_ID / Control_Title
        # (this is what gets downloaded by default)
        # ------------------------------------------------------------------
        crosswalk_df = build_crosswalk_view(
            working_df, id_col, title_col, selected_frameworks, include_scores
        )

        st.subheader("Crosswalk (check_id + finding title -> matched control per framework)")
        st.dataframe(crosswalk_df, use_container_width=True)

        # Summary of confidence distribution per framework
        st.subheader("Match confidence summary")
        summary_cols = st.columns(len(selected_frameworks))
        for i, fw in enumerate(selected_frameworks):
            prefix = framework_prefix(fw)
            with summary_cols[i]:
                st.markdown(f"**{fw}**")
                st.write(working_df[f"{prefix}_Confidence"].value_counts())

        with st.expander("Show full dataset (original columns + every framework match)"):
            st.dataframe(working_df, use_container_width=True)

        # Downloads
        st.subheader("Step 5 - Download your crosswalk")
        st.caption(
            "The CSV/Excel below contain check_id + finding title first, then each selected "
            "framework's matched Control_ID / Control_Title in the order you selected them - "
            "no other original finding columns are included."
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")

        crosswalk_csv_bytes = crosswalk_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Crosswalk CSV",
            data=crosswalk_csv_bytes,
            file_name=f"cloudguardian_crosswalk_{timestamp}.csv",
            mime="text/csv",
            type="primary",
        )

        crosswalk_excel_buffer = io.BytesIO()
        with pd.ExcelWriter(crosswalk_excel_buffer, engine="openpyxl") as writer:
            crosswalk_df.to_excel(writer, index=False, sheet_name="Crosswalk")
        st.download_button(
            "Download Crosswalk Excel",
            data=crosswalk_excel_buffer.getvalue(),
            file_name=f"cloudguardian_crosswalk_{timestamp}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        with st.expander("Need the full dataset instead? (all original columns + every framework match)"):
            full_csv_bytes = working_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download Full Dataset CSV",
                data=full_csv_bytes,
                file_name=f"cloudguardian_crosswalk_full_{timestamp}.csv",
                mime="text/csv",
            )

            full_excel_buffer = io.BytesIO()
            with pd.ExcelWriter(full_excel_buffer, engine="openpyxl") as writer:
                working_df.to_excel(writer, index=False, sheet_name="Crosswalk_Full")
            st.download_button(
                "Download Full Dataset Excel",
                data=full_excel_buffer.getvalue(),
                file_name=f"cloudguardian_crosswalk_full_{timestamp}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
else:
    st.info("Upload a CSV/Excel file to get started.")
