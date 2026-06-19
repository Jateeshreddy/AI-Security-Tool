import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def scan_file(uploaded_file):

    headers = {
        "x-apikey": API_KEY
    }

    files = {
        "file": (
            uploaded_file.name,
            uploaded_file.getvalue()
        )
    }

    upload_response = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers,
        files=files
    )

    if upload_response.status_code != 200:
        return {"error": upload_response.text}

    analysis_id = upload_response.json()["data"]["id"]

    time.sleep(10)

    result_response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    if result_response.status_code != 200:
        return {"error": result_response.text}

    return result_response.json()