"""
heuristics.py – Local heuristic rule engine for URL risk scoring (v2).

v2 additions:
  • Brand impersonation detection (checks domain for known brand names on non-official domains)

Flags returned are human-readable strings describing what was detected.
"""

import re
from urllib.parse import urlparse


# ── Known brands and their legitimate domains ──
BRAND_DOMAINS: dict[str, set[str]] = {
    "trezor":     {"trezor.io", "trezor.com"},
    "metamask":   {"metamask.io", "metamask.com"},
    "ledger":     {"ledger.com"},
    "paypal":     {"paypal.com", "paypal.me"},
    "coinbase":   {"coinbase.com"},
    "binance":    {"binance.com", "binance.us"},
    "apple":      {"apple.com", "icloud.com"},
    "google":     {"google.com", "google.co.in", "gmail.com", "accounts.google.com"},
    "microsoft":  {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "amazon":     {"amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"},
    "netflix":    {"netflix.com"},
    "facebook":   {"facebook.com", "fb.com"},
    "instagram":  {"instagram.com"},
    "twitter":    {"twitter.com", "x.com"},
    "whatsapp":   {"whatsapp.com", "web.whatsapp.com"},
    "chase":      {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "hdfc":       {"hdfcbank.com", "hdfcbank.net"},
    "sbi":        {"sbi.co.in", "onlinesbi.sbi"},
    "icici":      {"icicibank.com"},
    "phonepe":    {"phonepe.com"},
    "paytm":      {"paytm.com"},
    "gpay":       {"pay.google.com"},
    "stripe":     {"stripe.com"},
    "shopify":    {"shopify.com"},
    "dropbox":    {"dropbox.com"},
    "linkedin":   {"linkedin.com"},
    "github":     {"github.com", "github.io"},
    "discord":    {"discord.com", "discord.gg"},
    "steam":      {"steampowered.com", "steamcommunity.com"},
    "epic":       {"epicgames.com"},
    "roblox":     {"roblox.com"},
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".buzz", ".work", ".click", ".link", ".info", ".site",
    ".online", ".icu", ".cam", ".rest",
}

# Dangerous file extensions in URLs
DANGEROUS_EXTENSIONS = {".apk", ".exe", ".msi", ".bat", ".cmd", ".scr", ".dll", ".zip", ".rar", ".7z"}

# Known URL shortener domains
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd",
    "buff.ly", "ow.ly", "rebrand.ly", "shorturl.at", "cutt.ly",
}


def _get_registered_domain(host: str) -> str:
    """Extract registered domain from hostname."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def run_heuristics(url: str) -> list[str]:
    """Analyse a URL and return a list of heuristic flags."""
    flags: list[str] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    # 1. HTTP (not HTTPS)
    if parsed.scheme == "http":
        flags.append("Insecure Connection")

    # 2. IP address as host
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        flags.append("IP Address URL")

    # 3. Punycode / homograph
    if host.startswith("xn--") or any(part.startswith("xn--") for part in host.split(".")):
        flags.append("Punycode/Homograph Domain")

    # 4. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            flags.append(f"Suspicious TLD ({tld})")
            break

    # 5. Excessive subdomains (>3 dots in hostname)
    if host.count(".") > 3:
        flags.append(f"Excessive Subdomains ({host.count('.')} levels)")

    # 6. Long URL (>100 chars)
    if len(url) > 100:
        flags.append(f"Long URL ({len(url)} chars)")

    # 7. URL shortener
    registered = _get_registered_domain(host)
    if registered in SHORTENERS or host in SHORTENERS:
        flags.append("URL Shortener")

    # 8. Port in URL
    if parsed.port and parsed.port not in (80, 443):
        flags.append(f"Port in URL (:{parsed.port})")

    # 9. @ symbol (credential-based phishing trick)
    if "@" in parsed.netloc:
        flags.append("@ Symbol in URL")

    # 10. Dangerous file extension
    for ext in DANGEROUS_EXTENSIONS:
        if path.lower().endswith(ext):
            flags.append(f"Dangerous File Extension ({ext})")
            break

    # 11. Excessive URL-encoded characters
    encoded_count = full.count("%")
    if encoded_count > 5:
        flags.append(f"URL-Encoded Characters ({encoded_count}x)")

    # 12. Data URI
    if full.startswith("data:"):
        flags.append("Data URI")

    # ── 13. Brand Impersonation (NEW) ──
    host_lower = host.lower()
    registered_lower = registered.lower()
    for brand, legit_domains in BRAND_DOMAINS.items():
        # Check if brand name appears in the domain
        if brand in host_lower:
            # Check if the registered domain is NOT one of the legitimate domains
            if registered_lower not in legit_domains:
                flags.append(
                    f"Brand Impersonation ({brand}) – domain '{registered}' "
                    f"is not an official {brand} domain"
                )
                break  # one brand match is enough

    return flags
