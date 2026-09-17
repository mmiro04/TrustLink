import os
import time
import requests
from dotenv import load_dotenv


load_dotenv()


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY
}


def check_virustotal(url: str):

    result = {
        "available": False,
        "status": None,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "error": None
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VirusTotal API key not configured"
        return result

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=VT_HEADERS,
            files={
                "url": (None, url)
            },
            timeout=10
        )

        if response.status_code != 200:
            result["error"] = (
                f"VirusTotal API returned "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )
            return result

        analysis_id = response.json()["data"]["id"]

        analysis_url = (
            f"https://www.virustotal.com/api/v3/analyses/"
            f"{analysis_id}"
        )

        for _ in range(10):

            analysis_response = requests.get(
                analysis_url,
                headers=VT_HEADERS,
                timeout=10
            )

            if analysis_response.status_code != 200:
                result["error"] = (
                    f"VirusTotal analysis request returned "
                    f"HTTP {analysis_response.status_code}: "
                    f"{analysis_response.text}"
                )
                return result

            data = analysis_response.json()["data"]
            attributes = data["attributes"]

            status = attributes.get("status")

            result["status"] = status

            if status == "completed":

                stats = attributes.get("stats", {})

                result["available"] = True
                result["malicious"] = stats.get("malicious", 0)
                result["suspicious"] = stats.get("suspicious", 0)
                result["harmless"] = stats.get("harmless", 0)
                result["undetected"] = stats.get("undetected", 0)

                return result

            time.sleep(2)

        result["error"] = (
            "VirusTotal analysis did not complete within "
            "the timeout period"
        )

    except requests.RequestException as e:
        result["error"] = str(e)

    return result
