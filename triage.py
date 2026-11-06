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
def check_virustotal(ip):
    """Check an IP address against VirusTotal."""

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        raise ValueError("VirusTotal API key not configured")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": api_key,
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=15,
    )

    response.raise_for_status()

    data = response.json()["data"]["attributes"]

    stats = data["last_analysis_stats"]

    return {
        "ip": ip,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

if __name__ == "__main__":
    ip = input("Enter an IP address to investigate: ")

    try:
        abuse_result = check_ip(ip)
        vt_result = check_virustotal(ip)

        print("\n--- AbuseIPDB Results ---")
        print(f"IP: {abuse_result['ip']}")
        print(f"Abuse Confidence Score: {abuse_result['abuse_score']}%")
        print(f"Total Reports: {abuse_result['total_reports']}")

        print("\n--- VirusTotal Results ---")
        print(f"IP: {vt_result['ip']}")
        print(f"Malicious: {vt_result['malicious']}")
        print(f"Suspicious: {vt_result['suspicious']}")
        print(f"Harmless: {vt_result['harmless']}")
        print(f"Undetected: {vt_result['undetected']}")

    except requests.RequestException as error:
        print(f"API request failed: {error}")

    except ValueError as error:
        print(f"Configuration error: {error}")
