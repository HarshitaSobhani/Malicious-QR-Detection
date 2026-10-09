"""
verdict_engine.py – Aggregates all signals into a final SAFE / SUSPICIOUS / DANGEROUS verdict.

UPDATED: Now handles both string (legacy) and dict (new with viral phish) formats from PhishTank.

Scoring weights (v2 – updated):
  ┌────────────────────────┬────────┬──────────────────────────────────┐
  │ Signal                 │ Weight │ Notes                            │
  ├────────────────────────┼────────┼──────────────────────────────────┤
  │ Google Safe Browsing   │  0.35  │ Highest trust single signal      │
  │ PhishTank              │  0.30  │ Community-verified phishing DB   │
  │ Heuristic flags        │  ≤0.40 │ Capped; per-flag weights below   │
  │ ML classifier          │  0.20  │ Scaled by model confidence       │
  │ Redirect chain risk    │  0.20  │ NEW: from redirect_tracer        │
  │ WHOIS / domain age     │  0.25  │ NEW: from whois_checker          │
  └────────────────────────┴────────┴──────────────────────────────────┘

  Total can exceed 1.0 → clamped to 1.0.
  Verdict thresholds:
    score >= 0.60  →  DANGEROUS
    score >= 0.25  →  SUSPICIOUS
    score <  0.25  →  SAFE
"""


# Per-heuristic flag weights
HEURISTIC_WEIGHTS: dict[str, float] = {
    "Insecure Connection":              0.03,
    "IP Address URL":                   0.12,
    "Punycode/Homograph Domain":        0.14,
    "Suspicious TLD":                   0.06,
    "Excessive Subdomains":             0.08,
    "Long URL":                         0.04,
    "URL Shortener":                    0.05,
    "Port in URL":                      0.06,
    "@ Symbol in URL":                  0.12,
    "Dangerous File Extension":         0.10,
    "URL-Encoded Characters":           0.05,
    "Data URI":                         0.14,
    "Brand Impersonation":              0.18,
}


def aggregate_verdict(
    gsb_result: str,
    phishtank_result: str | dict,
    heuristic_flags: list[str],
    ml_score: float | None,
    redirect_risk: float = 0.0,
    whois_risk: float = 0.0,
) -> tuple[str, float]:
    """
    Combine all risk signals into (verdict, score).

    Args:
        gsb_result:      Google Safe Browsing result string
        phishtank_result: PhishTank result (string OR dict) - can be dict from updated check_phishtank
        heuristic_flags: List of heuristic flag strings
        ml_score:        ML model probability (0.0-1.0) or None
        redirect_risk:   Risk score from redirect chain analysis (0.0-1.0)
        whois_risk:      Risk score from WHOIS/domain age check (0.0-1.0)
    
    Returns:
        (verdict: str, score: float) where verdict is "dangerous", "suspicious", or "safe"
    """
    score = 0.0

    # ── GSB ──
    if gsb_result not in ("no match", "api_key_missing", "error", "n/a"):
        score += 0.35

    # ── PhishTank ──
    # UPDATED: Handle both string (legacy) and dict (new with viral detection) formats
    if isinstance(phishtank_result, dict):
        pt_status = phishtank_result.get("status", "n/a")
    else:
        pt_status = phishtank_result
    
    if pt_status == "phish":
        score += 0.30
    elif pt_status == "unverified_phish":
        score += 0.12

    # ── Heuristics ──
    heuristic_total = 0.0
    for flag in heuristic_flags:
        # Strip "(original URL)" suffix if present
        clean_flag = flag.replace(" (original URL)", "").strip()

        w = HEURISTIC_WEIGHTS.get(clean_flag)
        if w is None:
            # Prefix matching for parameterised flags
            for key, weight in HEURISTIC_WEIGHTS.items():
                if clean_flag.startswith(key.split("(")[0].strip()):
                    w = weight
                    break
            if w is None:
                w = 0.06  # default for unknown flags
        heuristic_total += w

    score += min(heuristic_total, 0.40)  # cap heuristic contribution

    # ── ML ──
    if ml_score is not None:
        score += ml_score * 0.20

    # ── Redirect chain risk (NEW) ──
    score += redirect_risk * 0.20

    # ── WHOIS / domain age risk (NEW) ──
    score += whois_risk * 0.25

    # Clamp
    score = round(min(score, 1.0), 2)

    # ── Map to verdict ──
    if score >= 0.60:
        verdict = "dangerous"
    elif score >= 0.25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return verdict, score
