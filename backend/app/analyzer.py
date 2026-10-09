"""
analyzer.py – Orchestrates the full QR analysis pipeline.

Pipeline (v3 - UPDATED):
  1. Detect content type (URL / UPI / plain text)
  2. Expand redirects (httpx) + analyze redirect chain for discrepancies
  3. WHOIS domain age check
  4. Google Safe Browsing check
  5. PhishTank check
  6. [UPDATED] Check if ANY phish detected - if yes, return immediately with "dangerous"
  7. Heuristic rule engine (now includes brand impersonation)
  8. ML inference (scikit-learn / XGBoost)
  9. Aggregate verdict (updated weights for new signals)
"""

import re
from datetime import datetime, timezone

from .redirect_tracer import expand_redirects, analyze_redirect_chain
from .whois_checker import check_domain_age
from .gsb_client import check_gsb
from .phishtank_client import check_phishtank
from .heuristics import run_heuristics
from .ml_classifier import predict_url
from .verdict_engine import aggregate_verdict


# ── URL extraction helpers ───────────────────────────────────────────
_URL_RE = re.compile(r"(https?://\S+)", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(/\S*)?")
_UPI_RE = re.compile(r"^upi://", re.IGNORECASE)


def _detect_type(raw: str) -> tuple[str, str | None]:
    """Return (content_type, url_or_none)."""
    if _UPI_RE.match(raw):
        return "upi", None

    m = _URL_RE.search(raw)
    if m:
        return "url", m.group(1)

    m2 = _DOMAIN_RE.search(raw)
    if m2:
        return "url", f"http://{m2.group(0)}"

    return "text", None


# ── Main entry point ─────────────────────────────────────────────────
async def full_analysis(raw: str) -> dict:
    content_type, url = _detect_type(raw)

    # Defaults for non-URL content
    redirect_chain: list[dict] = []
    redirect_analysis: dict = {}
    whois_info: dict = {}
    final_url: str | None = None
    gsb_result = "n/a"
    phishtank_result = "n/a"
    heuristic_flags: list[str] = []
    ml_score: float | None = None
    reasons: list[str] = []

    if content_type == "url" and url:
        # ── Step 1: Redirect expansion + chain analysis ──
        redirect_chain, final_url = await expand_redirects(url)
        redirect_analysis = analyze_redirect_chain(redirect_chain, url, final_url or url)

        # Add redirect flags to reasons
        for flag in redirect_analysis.get("flags", []):
            reasons.append(f"Redirect: {flag}")

        target = final_url or url

        # ── Step 2: WHOIS domain age check ──
        whois_info = await check_domain_age(target)
        for flag in whois_info.get("flags", []):
            reasons.append(f"WHOIS: {flag}")

        # ── Step 3: Google Safe Browsing ──
        gsb_result = await check_gsb(target)
        if gsb_result not in ("no match", "api_key_missing", "error", "n/a"):
            reasons.append(f"GSB: {gsb_result}")

        # Also check the ORIGINAL url if it differs from final
        if final_url and final_url != url:
            gsb_orig = await check_gsb(url)
            if gsb_orig not in ("no match", "api_key_missing", "error", "n/a"):
                reasons.append(f"GSB (original URL): {gsb_orig}")
                if gsb_result == "no match":
                    gsb_result = gsb_orig  # upgrade the verdict signal

        # ── Step 4: PhishTank ──
        phishtank_result = await check_phishtank(target)
        
        # ╔═══════════════════════════════════════════════════════════════════╗
        # ║ UPDATED: Check if ANY phish detected - return immediately        ║
        # ║ No viral threshold - ANY valid phish = DANGEROUS                  ║
        # ╚═══════════════════════════════════════════════════════════════════╝
        if isinstance(phishtank_result, dict) and phishtank_result.get("is_phish"):
            return {
                "content_type": content_type,
                "raw": raw,
                "final_url": final_url or target,
                "redirect_chain": redirect_chain,
                "redirect_analysis": redirect_analysis,
                "whois_info": whois_info,
                "verdict": "dangerous",
                "score": 1.0,
                "reasons": [
                    "Phishing URL detected in PhishTank database",
                    f"Status: {phishtank_result.get('status')}",
                    f"Reports: {phishtank_result.get('valid_reports', 0)} total",
                    f"Detail: {phishtank_result.get('phish_detail_page', '')}",
                ],
                "gsb_result": gsb_result,
                "phishtank_result": phishtank_result,
                "heuristic_flags": [],
                "ml_score": None,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            }
        
        # Handle both dict (new format) and string (old format) results
        if isinstance(phishtank_result, dict):
            pt_status = phishtank_result.get("status", "n/a")
        else:
            pt_status = phishtank_result
            
        if pt_status not in ("not_listed", "error", "n/a"):
            reasons.append(f"PhishTank: {pt_status}")

        # ── Step 5: Heuristics (run on both original and final URL) ──
        heuristic_flags = run_heuristics(target)

        # Also check original URL for heuristic flags not caught on final
        if final_url and final_url != url:
            orig_flags = run_heuristics(url)
            for flag in orig_flags:
                if flag not in heuristic_flags:
                    heuristic_flags.append(f"{flag} (original URL)")

        for flag in heuristic_flags:
            reasons.append(f"Heuristic: {flag}")

        # ── Step 6: ML classification ──
        ml_score = predict_url(target)
        if ml_score is not None and ml_score >= 0.5:
            reasons.append(f"ML risk: {ml_score:.0%}")

    elif content_type == "upi":
        reasons.append("UPI content – no URL to analyze")

    else:
        reasons.append("Plain text – no URL detected")

    # ── Step 7: Aggregate verdict (with new signals) ──
    verdict, score = aggregate_verdict(
        gsb_result=gsb_result,
        phishtank_result=phishtank_result,
        heuristic_flags=heuristic_flags,
        ml_score=ml_score,
        redirect_risk=redirect_analysis.get("risk_score", 0.0),
        whois_risk=whois_info.get("risk_score", 0.0),
    )

    return {
        "content_type": content_type,
        "raw": raw,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "redirect_analysis": redirect_analysis,
        "whois_info": whois_info,
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "gsb_result": gsb_result,
        "phishtank_result": phishtank_result,
        "heuristic_flags": heuristic_flags,
        "ml_score": ml_score,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
