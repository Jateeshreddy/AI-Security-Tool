import streamlit as st

from services.virustotal_service import scan_url
from services.ip_service import scan_ip
from services.file_service import scan_file

from utils.risk_engine import calculate_risk_score
from services.gemini_service import generate_security_report

st.set_page_config(
    page_title="AI Security Assessment Tool",
    page_icon="🛡️"
)

st.title("🛡️ AI Security Assessment Tool")

scan_type = st.selectbox(
    "Select Scan Type",
    ["Website URL", "IP Address", "File Upload"]
)

if scan_type == "File Upload":
    uploaded_file = st.file_uploader(
        "Upload File",
        type=["pdf", "docx", "zip", "exe"]
    )
else:
    target = st.text_input("Enter URL or IP Address")

if st.button("Scan"):

    valid_input = (
        (scan_type != "File Upload" and target)
        or
        (scan_type == "File Upload" and uploaded_file)
    )

    if valid_input:

        if scan_type == "Website URL":
            result = scan_url(target)
            report_type = "Website"

        elif scan_type == "IP Address":
            result = scan_ip(target)
            report_type = "IP Address"

        else:
            result = scan_file(uploaded_file)
            report_type = "File"

        if "error" in result:
            st.error(result["error"])

        else:

            attributes = result["data"]["attributes"]

            if "last_analysis_stats" in attributes:
                stats = attributes["last_analysis_stats"]

            elif "stats" in attributes:
                stats = attributes["stats"]

            else:
                stats = attributes.get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            score, level = calculate_risk_score(
                malicious,
                suspicious
            )

            st.subheader("Security Results")

            st.write(f"Malicious Detections: {malicious}")
            st.write(f"Suspicious Detections: {suspicious}")
            st.write(f"Risk Score: {score}")
            st.write(f"Risk Level: {level}")

            report = generate_security_report(
                malicious,
                suspicious,
                score,
                level,
                report_type
            )

            st.subheader("AI Security Report")
            st.write(report)

    else:
        st.warning(
            "Please provide a URL, IP Address, or File"
        )