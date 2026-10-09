"""
whois_checker.py – Domain age and WHOIS-based risk assessment.

Checks:
  • Domain registration age (newly registered = high risk)
  • Registrar reputation
  • WHOIS privacy / redacted records
  • Domain expiry proximity (short-lived domains = suspicious)

Uses python-whois library. Falls back gracefully if WHOIS lookup fails
(many phishing domains block WHOIS or use privacy services).

Install:  pip install python-whois
"""

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse
from functools import lru_cache

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# Domains that are always safe – skip WHOIS for performance
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "apple.com", "microsoft.com", "github.com", "wikipedia.org",
    "twitter.com", "x.com", "linkedin.com", "instagram.com",
    "reddit.com", "netflix.com", "whatsapp.com", "trezor.io",
    "metamask.io", "paypal.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com",
}

# Registrars frequently used in phishing campaigns
SUSPICIOUS_REGISTRARS = {
    "namecheap",
    "namesilo",
    "dynadot",
    "porkbun",
    "hostinger",
    "regtons",
    "nicenic",
}


def _get_registered_domain(url: str) -> str:
    """Extract the registered domain (e.g., 'example.com') from a URL."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    # Simple extraction: take last 2 parts (or 3 for co.uk etc.)
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _sync_whois_lookup(domain: str) -> dict | None:
    """Perform synchronous WHOIS lookup (runs in thread pool)."""
    if not HAS_WHOIS:
        return None
    try:
        w = whois.whois(domain)
        if w is None or w.domain_name is None:
            return None
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
        }
    except Exception:
        return None


async def check_domain_age(url: str) -> dict:
    """
    Perform WHOIS lookup and assess domain risk based on age and metadata.

    Returns:
        {
            "domain": str,
            "age_days": int | None,
            "creation_date": str | None,
            "expiration_date": str | None,
            "registrar": str | None,
            "flags": [str],
            "risk_score": float (0.0 - 1.0),
            "whois_available": bool,
            "summary": str,
        }
    """
    domain = _get_registered_domain(url)
    now = datetime.now(timezone.utc)

    # Skip WHOIS for known trusted domains
    if domain in TRUSTED_DOMAINS:
        return {
            "domain": domain,
            "age_days": None,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "flags": [],
            "risk_score": 0.0,
            "whois_available": False,
            "summary": f"Trusted domain: {domain} – WHOIS check skipped.",
        }

    if not HAS_WHOIS:
        return {
            "domain": domain,
            "age_days": None,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "flags": ["python-whois not installed – domain age check unavailable"],
            "risk_score": 0.0,
            "whois_available": False,
            "summary": "WHOIS lookup unavailable – install python-whois for domain age checks.",
        }

    # Run WHOIS in thread pool to avoid blocking the async event loop
    loop = asyncio.get_event_loop()
    whois_data = await loop.run_in_executor(None, _sync_whois_lookup, domain)

    flags: list[str] = []
    risk_score = 0.0
    age_days = None
    creation_str = None
    expiration_str = None
    registrar = None

    if whois_data is None:
        flags.append("WHOIS lookup failed or data is redacted – cannot verify domain age")
        risk_score = 0.15  # mild risk from opacity
        return {
            "domain": domain,
            "age_days": None,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "flags": flags,
            "risk_score": risk_score,
            "whois_available": False,
            "summary": f"WHOIS data unavailable for {domain}. Domain cannot be age-verified.",
        }

    # ── Parse creation date ──
    creation_date = whois_data.get("creation_date")
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (now - creation_date).days
        creation_str = creation_date.strftime("%Y-%m-%d")

        # Age-based risk thresholds
        if age_days <= 7:
            flags.append(f"CRITICAL: Domain is only {age_days} day(s) old – very likely malicious")
            risk_score += 0.50
        elif age_days <= 30:
            flags.append(f"Domain registered {age_days} days ago – newly created, high phishing risk")
            risk_score += 0.35
        elif age_days <= 90:
            flags.append(f"Domain is {age_days} days old – relatively new, moderate risk")
            risk_score += 0.20
        elif age_days <= 180:
            flags.append(f"Domain is {age_days} days old – somewhat new")
            risk_score += 0.08
        # > 180 days: no flag, considered reasonably established

    else:
        flags.append("Creation date not available in WHOIS record")
        risk_score += 0.10

    # ── Parse expiration date ──
    exp_date = whois_data.get("expiration_date")
    if isinstance(exp_date, list):
        exp_date = exp_date[0]
    if isinstance(exp_date, datetime):
        if exp_date.tzinfo is None:
            exp_date = exp_date.replace(tzinfo=timezone.utc)
        expiration_str = exp_date.strftime("%Y-%m-%d")

        days_until_expiry = (exp_date - now).days
        if days_until_expiry < 0:
            flags.append("Domain has EXPIRED – may be parked or hijacked")
            risk_score += 0.20
        elif days_until_expiry <= 30:
            flags.append(f"Domain expires in {days_until_expiry} days – short-lived registration")
            risk_score += 0.10

        # Check for very short registration period (< 1 year from creation)
        if creation_date and isinstance(creation_date, datetime):
            total_registration = (exp_date - creation_date).days
            if total_registration <= 365 and age_days is not None and age_days <= 90:
                flags.append(
                    f"Short registration period ({total_registration} days) "
                    "– attackers register domains briefly"
                )
                risk_score += 0.10

    # ── Registrar check ──
    registrar = whois_data.get("registrar") or ""
    registrar_lower = registrar.lower() if registrar else ""
    for susp in SUSPICIOUS_REGISTRARS:
        if susp in registrar_lower:
            flags.append(
                f"Registrar '{registrar}' is commonly used in phishing campaigns "
                "(not inherently malicious, but correlates with abuse)"
            )
            risk_score += 0.05
            break

    # ── WHOIS privacy / redaction check ──
    org = whois_data.get("org") or ""
    emails = whois_data.get("emails") or []
    if isinstance(emails, str):
        emails = [emails]
    email_str = " ".join(emails).lower()

    privacy_indicators = ["privacy", "redacted", "withheld", "proxy", "protect", "whoisguard"]
    has_privacy = any(
        ind in (org.lower() + " " + email_str + " " + registrar_lower)
        for ind in privacy_indicators
    )
    if has_privacy and age_days is not None and age_days <= 90:
        flags.append("WHOIS privacy enabled on a new domain – common in phishing")
        risk_score += 0.10

    # Clamp risk score
    risk_score = round(min(risk_score, 1.0), 2)

    # ── Summary ──
    if not flags:
        summary = f"Domain {domain} is well-established. No WHOIS-based concerns."
    elif risk_score >= 0.40:
        summary = (
            f"HIGH RISK: Domain {domain} "
            + (f"is only {age_days} days old. " if age_days else "has no verifiable creation date. ")
            + f"{len(flags)} WHOIS-based concern(s) detected."
        )
    else:
        summary = f"Domain {domain} has {len(flags)} minor WHOIS-based note(s)."

    return {
        "domain": domain,
        "age_days": age_days,
        "creation_date": creation_str,
        "expiration_date": expiration_str,
        "registrar": registrar,
        "flags": flags,
        "risk_score": risk_score,
        "whois_available": True,
        "summary": summary,
    }
