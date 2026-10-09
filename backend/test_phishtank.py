"""
test_phishtank.py – Diagnostic script to debug PhishTank API integration.

Run this BEFORE starting the full server to verify PhishTank is working:

    cd backend
    python test_phishtank.py "https://managesuite-trezor.com/?input_24=..."

This will show you the exact request/response from PhishTank so you can
see what's happening.
"""

import sys
import asyncio
import json
import httpx
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("phishtank_test")


async def test_phishtank(url: str):
    print("=" * 70)
    print("PhishTank API Diagnostic Test")
    print("=" * 70)

    # Ensure URL has scheme
    check_url = url.strip()
    if not check_url.startswith("http://") and not check_url.startswith("https://"):
        check_url = f"https://{check_url}"

    print(f"\n[1] URL to check: {check_url[:100]}...")
    print(f"    Full URL length: {len(check_url)} chars")

    # Build the form data exactly as PhishTank expects
    form_data = {
        "url": check_url,
        "format": "json",
    }

    import os
    api_key = os.getenv("PHISHTANK_API_KEY", "")
    if api_key:
        form_data["app_key"] = api_key
        print(f"    API key: {api_key[:8]}...{api_key[-4:]}")
    else:
        print("    API key: NOT SET (using anonymous mode – 10 req/min)")

    headers = {
        "User-Agent": "phishtank/qr-sentinel-v2 (capstone-project; contact@qrsentinel.dev)",
    }

    print(f"\n[2] Sending POST to https://checkurl.phishtank.com/checkurl/")
    print(f"    Form data keys: {list(form_data.keys())}")
    print(f"    Headers: {headers}")

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=True) as client:
            resp = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=form_data,
                headers=headers,
            )

            print(f"\n[3] Response:")
            print(f"    HTTP status: {resp.status_code}")
            print(f"    Content-Type: {resp.headers.get('content-type', 'unknown')}")
            print(f"    Response length: {len(resp.text)} chars")

            if resp.status_code == 429:
                print("\n    ❌ RATE LIMITED! Wait a minute and try again.")
                print("    Tip: Set PHISHTANK_API_KEY env var for 100 req/min.")
                return

            if resp.status_code != 200:
                print(f"\n    ❌ Unexpected status code!")
                print(f"    Body: {resp.text[:500]}")
                return

            # Show raw response
            raw = resp.text
            print(f"\n[4] Raw response (first 500 chars):")
            print(f"    {raw[:500]}")

            # Parse JSON
            try:
                data = resp.json()
            except json.JSONDecodeError as e:
                print(f"\n    ❌ JSON parse error: {e}")
                print(f"    This means PhishTank returned non-JSON (maybe HTML error page)")
                return

            print(f"\n[5] Parsed JSON structure:")
            print(f"    Top-level keys: {list(data.keys())}")

            results = data.get("results", {})
            print(f"    results keys: {list(results.keys())}")

            # Show each field with type
            for key in ["url", "in_database", "phish_id", "phish_detail_page", "verified", "verified_at", "valid"]:
                val = results.get(key)
                print(f"    results.{key} = {val!r}  (type: {type(val).__name__})")

            # Parse verdict
            in_database = results.get("in_database")
            verified = results.get("verified")
            valid = results.get("valid")

            def to_bool(val) -> bool:
                if isinstance(val, bool):
                    return val
                if isinstance(val, str):
                    return val.lower().strip() == "true"
                return False

            is_in_db = to_bool(in_database)
            is_verified = to_bool(verified)
            is_valid = to_bool(valid)

            print(f"\n[6] Verdict:")
            print(f"    in_database: {in_database!r} → {is_in_db}")
            print(f"    verified:    {verified!r} → {is_verified}")
            print(f"    valid:       {valid!r} → {is_valid}")

            if is_in_db:
                if is_verified and is_valid:
                    print(f"\n    ✅ RESULT: PHISH (confirmed & verified)")
                elif is_verified and not is_valid:
                    print(f"\n    ℹ️  RESULT: NOT PHISH (verified as false positive)")
                else:
                    print(f"\n    ⚠️  RESULT: UNVERIFIED PHISH (in DB but not yet verified)")
            else:
                print(f"\n    ℹ️  RESULT: NOT LISTED in PhishTank database")

            # Show phish detail page if available
            detail = results.get("phish_detail_page")
            if detail:
                print(f"\n    PhishTank detail page: {detail}")

    except httpx.TimeoutException:
        print(f"\n    ❌ TIMEOUT! PhishTank didn't respond within 15 seconds.")
    except httpx.ConnectError as e:
        print(f"\n    ❌ CONNECTION ERROR: {e}")
    except Exception as e:
        print(f"\n    ❌ UNEXPECTED ERROR: {type(e).__name__}: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_phishtank.py <url>")
        print("Example: python test_phishtank.py 'https://managesuite-trezor.com/?input_24=...'")
        sys.exit(1)

    url = sys.argv[1]
    asyncio.run(test_phishtank(url))
