import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip(ip):
    """Check an IP address against AbuseIPDB."""

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=15,
    )

    response.raise_for_status()

    data = response.json()["data"]

    return {
        "ip": data["ipAddress"],
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data.get("countryCode", "Unknown"),
        "is_public": data.get("isPublic", False),
    }


if __name__ == "__main__":
    ip = input("Enter an IP address to investigate: ")

    try:
        result = check_ip(ip)

        print("\n--- AbuseIPDB Results ---")
        print(f"IP: {result['ip']}")
        print(f"Abuse Confidence Score: {result['abuse_score']}%")
        print(f"Total Reports: {result['total_reports']}")
        print(f"Country: {result['country']}")
        print(f"Public IP: {result['is_public']}")

    except requests.RequestException as error:
        print(f"API request failed: {error}")
