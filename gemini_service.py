import os
from datetime import datetime
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

model = genai.GenerativeModel("gemini-2.5-flash")


def generate_security_report(
    malicious,
    suspicious,
    score,
    level,
    scan_type="Website"
):

    current_date = datetime.now().strftime("%d-%m-%Y")

    prompt = f"""
Generate a professional cybersecurity report.

Title:
{scan_type} Security Assessment Report

Assessment Date: {current_date}

Security Results:
- Malicious Detections: {malicious}
- Suspicious Detections: {suspicious}
- Risk Score: {score}
- Risk Level: {level}

Generate the report in the following format:

# {scan_type} Security Assessment Report

Assessment Date: {current_date}

## 1. Executive Summary

Provide a concise executive summary of the findings.

## 2. Risk Analysis

Analyze:
- Malicious detections
- Suspicious detections
- Risk score
- Risk level

Explain their impact.

## 3. Security Recommendations

Provide actionable security recommendations based on the findings.

## 4. Conclusion

Provide a final conclusion about the security posture.

Keep the report professional and detailed.
"""

    response = model.generate_content(prompt)

    return response.text