import httpx
import os
import asyncio

GSB_API_KEY = os.getenv("GSB_API_KEY", "")

async def gsb_check(url: str) -> bool:
    if not GSB_API_KEY:
        print("GSB: key missing")
        return False

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={GSB_API_KEY}"
    )

    payload = {
        "client": {"clientId": "qr-sentinel", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await asyncio.wait_for(
                client.post(endpoint, json=payload),
                timeout=3.0  # HARD cutoff
            )

        if response.status_code != 200:
            print("GSB HTTP error:", response.status_code)
            return False

        data = response.json()
        return bool(data.get("matches"))

    except asyncio.TimeoutError:
        print("GSB timeout — skipping")
        return False

    except Exception as e:
        print("GSB exception:", e)
        return False