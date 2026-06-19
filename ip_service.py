import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def scan_ip(ip):

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers=headers
    )

    if response.status_code != 200:
        return {"error": response.text}

    return response.json()
