import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def scan_url(url):

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return {"error": response.text}

    analysis_id = response.json()["data"]["id"]

    time.sleep(5)

    analysis_response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    return analysis_response.json()
if __name__ == "__main__":
    print("VirusTotal Key:", API_KEY)
