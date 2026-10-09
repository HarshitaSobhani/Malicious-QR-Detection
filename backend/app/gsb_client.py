"""
gsb_client.py – Google Safe Browsing v4 Lookup API client.

Set env var  GSB_API_KEY  to your Google Cloud API key.
If not set, returns "api_key_missing" (graceful degradation).
"""

import os
import httpx

GSB_API_KEY = os.getenv("GSB_API_KEY", "")
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_gsb(url: str) -> str:
    """
    Query Google Safe Browsing v4 for `url`.
    Returns:
        "no match"           – URL not in threat lists
        "SOCIAL_ENGINEERING" – phishing
        "MALWARE"            – malware
        "UNWANTED_SOFTWARE"  – PUP
        etc.
        "api_key_missing"    – GSB key not configured
        "error"              – API call failed
    """
    if not GSB_API_KEY:
        return "api_key_missing"

    payload = {
        "client": {
            "clientId": "qr-sentinel",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(
                GSB_ENDPOINT,
                params={"key": GSB_API_KEY},
                json=payload,
            )
            data = resp.json()

        matches = data.get("matches")
        if not matches:
            return "no match"

        # Return the first threat type found
        return matches[0].get("threatType", "unknown")

    except Exception:
        return "error"
