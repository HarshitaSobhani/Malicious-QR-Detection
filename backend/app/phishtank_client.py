"""
phishtank_client.py – PhishTank URL check with auto-dangerous for ANY phish

Set env var  PHISHTANK_API_KEY  for higher rate limits.
Works without a key at reduced rate.

FEATURE: ANY valid phish (not just viral) = auto-dangerous, no further analysis needed.
"""
import os
import httpx
import logging

logger = logging.getLogger("phishtank_client")

PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")
PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"


async def check_phishtank(url: str) -> dict:
    """
    Check if `url` is a known phish in PhishTank.
    
    UPDATED: ANY valid phish = auto-dangerous (no viral threshold)
    
    Returns dict:
        {
            'status': 'phish' | 'unverified_phish' | 'not_listed' | 'error',
            'is_phish': bool,
            'verdict': 'dangerous' | 'suspicious' | 'safe' | None,
            'recent_reports': int,
            'valid_reports': int,
            'phish_detail_page': str,
        }
    
    IMPORTANT:
    If is_phish=True (any phish, viral or not), verdict='dangerous'
    Caller should return 'dangerous' immediately and skip all other analysis.
    """
    form_data = {
        "url": url,
        "format": "json",
    }
    if PHISHTANK_API_KEY:
        form_data["app_key"] = PHISHTANK_API_KEY

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                PHISHTANK_ENDPOINT,
                data=form_data,
                headers={"User-Agent": "phishtank/qr-sentinel"},
            )
            data = resp.json()

        results = data.get("results", {})
        in_database = results.get("in_database", False)

        # Extract report counts from API response
        recent_reports = int(results.get("recent", 0))
        valid_reports = int(results.get("valid_reports", 0))
        phish_detail = results.get("phish_detail_page", "")

        if in_database:
            verified = results.get("verified")
            valid = results.get("valid")

            # Convert to bool (PhishTank might return string "true"/"false")
            is_verified = (
                verified is True
                if isinstance(verified, bool)
                else str(verified).lower() == "true"
            )
            is_valid = (
                valid is True
                if isinstance(valid, bool)
                else str(valid).lower() == "true"
            )

            if is_verified and is_valid:
                status = "phish"
                is_phish = True
            else:
                status = "unverified_phish"
                is_phish = False  # Still phish, just not verified yet

            # UPDATED LOGIC: ANY phish = dangerous (no viral check needed)
            if is_phish:
                verdict = "dangerous"  # AUTO-DANGEROUS for ANY phish
                logger.warning(
                    f"PHISH DETECTED - Auto-dangerous: {url} | "
                    f"Status: {status}, Recent: {recent_reports}, Valid: {valid_reports}"
                )
            else:
                verdict = "safe"

            return {
                "status": status,
                "is_phish": is_phish,
                "verdict": verdict,
                "recent_reports": recent_reports,
                "valid_reports": valid_reports,
                "phish_detail_page": phish_detail,
            }

        # Not in database
        return {
            "status": "not_listed",
            "is_phish": False,
            "verdict": "safe",
            "recent_reports": 0,
            "valid_reports": 0,
            "phish_detail_page": "",
        }

    except Exception as e:
        logger.error(f"PhishTank API error: {e}")
        return {
            "status": "error",
            "is_phish": False,
            "verdict": None,
            "recent_reports": 0,
            "valid_reports": 0,
            "phish_detail_page": "",
        }
