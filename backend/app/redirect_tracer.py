"""
redirect_tracer.py – Enhanced redirect chain tracer with discrepancy detection.

Improvements over v1:
  • Detects domain changes across redirect hops (cross-domain redirects)
  • Detects TLD changes (e.g., .com → .xyz) as suspicious
  • Flags excessive redirect depth (> 3 hops)
  • Detects protocol downgrades (HTTPS → HTTP)
  • Captures HTML meta-refresh and JavaScript-based redirects
  • Returns structured redirect_analysis with flags
  • Checks both HEAD and GET for more reliable chain tracing
"""

import re
import httpx
from urllib.parse import urlparse


MAX_REDIRECTS = 15
TIMEOUT = 10.0  # seconds per hop


def _extract_domain(url: str) -> str:
    """Extract the registered domain from a URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.lower()


def _extract_tld(url: str) -> str:
    """Extract TLD from a URL."""
    domain = _extract_domain(url)
    parts = domain.split(".")
    return f".{parts[-1]}" if parts else ""


def _extract_meta_refresh(html: str) -> str | None:
    """Extract URL from HTML meta-refresh tag."""
    # <meta http-equiv="refresh" content="0;url=https://...">
    pattern = re.compile(
        r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'\s>]+)',
        re.IGNORECASE,
    )
    match = pattern.search(html)
    if match:
        return match.group(1).strip()
    return None


def _extract_js_redirect(html: str) -> str | None:
    """Extract URL from common JavaScript redirect patterns."""
    patterns = [
        # window.location = "..."
        re.compile(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
        # window.location.replace("...")
        re.compile(r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
        # document.location = "..."
        re.compile(r'document\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    ]
    for pat in patterns:
        match = pat.search(html)
        if match:
            return match.group(1).strip()
    return None


def _resolve_relative(base_url: str, location: str) -> str:
    """Resolve a potentially relative URL against a base URL."""
    if location.startswith("http://") or location.startswith("https://"):
        return location
    parsed = urlparse(base_url)
    if location.startswith("//"):
        return f"{parsed.scheme}:{location}"
    if location.startswith("/"):
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    # Relative path
    base_path = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else ""
    return f"{parsed.scheme}://{parsed.netloc}{base_path}/{location}"


async def expand_redirects(url: str) -> tuple[list[dict], str]:
    """
    Follow redirects and return (chain, final_url).
    Each hop: {
        "url": str,
        "status": int,
        "location": str | None,
        "redirect_type": str  ("http_301" | "http_302" | "meta_refresh" | "js_redirect" | "final" | "error")
    }
    """
    chain: list[dict] = []
    current = url

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=TIMEOUT,
        verify=False,
    ) as client:
        for hop_num in range(MAX_REDIRECTS):
            try:
                # Try HEAD first (faster)
                resp = await client.head(current, follow_redirects=False)
                # If HEAD returns 405 Method Not Allowed, fall back to GET
                if resp.status_code == 405:
                    resp = await client.get(current, follow_redirects=False)
            except httpx.RequestError:
                try:
                    resp = await client.get(current, follow_redirects=False)
                except httpx.RequestError as e:
                    chain.append({
                        "url": current,
                        "status": 0,
                        "location": None,
                        "redirect_type": "error",
                        "error": str(e),
                    })
                    break

            location = resp.headers.get("location")

            # Check for HTTP redirect (3xx)
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                resolved = _resolve_relative(current, location)
                chain.append({
                    "url": current,
                    "status": resp.status_code,
                    "location": resolved,
                    "redirect_type": f"http_{resp.status_code}",
                })
                current = resolved
                continue

            # If 200, check for meta-refresh or JS redirect in HTML
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "")
                if "text/html" in content_type:
                    # Need body for meta/JS checks – re-fetch with GET if we used HEAD
                    try:
                        if resp.request.method == "HEAD":
                            body_resp = await client.get(current, follow_redirects=False)
                            html = body_resp.text
                        else:
                            html = resp.text
                    except httpx.RequestError:
                        html = ""

                    # Check meta-refresh
                    meta_url = _extract_meta_refresh(html)
                    if meta_url:
                        resolved = _resolve_relative(current, meta_url)
                        chain.append({
                            "url": current,
                            "status": resp.status_code,
                            "location": resolved,
                            "redirect_type": "meta_refresh",
                        })
                        current = resolved
                        continue

                    # Check JS redirect
                    js_url = _extract_js_redirect(html)
                    if js_url and js_url != current:
                        resolved = _resolve_relative(current, js_url)
                        chain.append({
                            "url": current,
                            "status": resp.status_code,
                            "location": resolved,
                            "redirect_type": "js_redirect",
                        })
                        current = resolved
                        continue

            # No more redirects – this is the final destination
            chain.append({
                "url": current,
                "status": resp.status_code,
                "location": None,
                "redirect_type": "final",
            })
            break

    final_url = current
    return chain, final_url


def analyze_redirect_chain(chain: list[dict], original_url: str, final_url: str) -> dict:
    """
    Analyze the redirect chain for suspicious patterns.

    Returns:
        {
            "total_hops": int,
            "domain_changes": int,
            "domains_visited": [str],
            "flags": [str],
            "risk_score": float (0.0 - 1.0),
            "summary": str,
        }
    """
    flags: list[str] = []
    domains_visited: list[str] = []

    # Collect all domains in order
    for hop in chain:
        domain = _extract_domain(hop["url"])
        if domain and (not domains_visited or domains_visited[-1] != domain):
            domains_visited.append(domain)

    total_hops = len(chain) - 1  # exclude the final landing
    if total_hops < 0:
        total_hops = 0
    domain_changes = max(0, len(domains_visited) - 1)

    # ── Flag 1: Excessive redirect depth ──
    if total_hops > 3:
        flags.append(f"Excessive redirects ({total_hops} hops) – legitimate sites rarely exceed 2-3")

    # ── Flag 2: Cross-domain redirects ──
    if domain_changes >= 2:
        flags.append(
            f"Multiple domain changes ({domain_changes}): {' → '.join(domains_visited)} "
            "– may be hiding final destination"
        )
    elif domain_changes == 1:
        orig_domain = _extract_domain(original_url)
        final_domain = _extract_domain(final_url)
        if orig_domain != final_domain:
            flags.append(
                f"Domain changed: {orig_domain} → {final_domain} "
                "– final site differs from displayed link"
            )

    # ── Flag 3: TLD change ──
    orig_tld = _extract_tld(original_url)
    final_tld = _extract_tld(final_url)
    if orig_tld and final_tld and orig_tld != final_tld:
        flags.append(f"TLD changed: {orig_tld} → {final_tld}")

    # ── Flag 4: Protocol downgrade ──
    orig_scheme = urlparse(original_url).scheme
    final_scheme = urlparse(final_url).scheme
    if orig_scheme == "https" and final_scheme == "http":
        flags.append("Protocol downgrade: HTTPS → HTTP (security reduced)")

    for hop in chain:
        if hop.get("redirect_type") == "meta_refresh":
            next_hop = hop.get("location", "")
            hop_scheme = urlparse(hop["url"]).scheme
            next_scheme = urlparse(next_hop).scheme if next_hop else ""
            if hop_scheme == "https" and next_scheme == "http":
                flags.append("Meta-refresh causes HTTPS → HTTP downgrade")
                break

    # ── Flag 5: Meta-refresh or JS redirect detected ──
    meta_hops = [h for h in chain if h.get("redirect_type") == "meta_refresh"]
    js_hops = [h for h in chain if h.get("redirect_type") == "js_redirect"]

    if meta_hops:
        flags.append(
            f"HTML meta-refresh redirect detected ({len(meta_hops)} hop(s)) "
            "– often used to evade scanners"
        )
    if js_hops:
        flags.append(
            f"JavaScript redirect detected ({len(js_hops)} hop(s)) "
            "– client-side redirect can hide malicious destinations"
        )

    # ── Flag 6: URL shortener in chain ──
    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd",
        "buff.ly", "ow.ly", "rebrand.ly", "shorturl.at", "cutt.ly",
        "rb.gy", "short.io", "lnkd.in",
    }
    shorteners_found = [d for d in domains_visited if d in SHORTENER_DOMAINS]
    if shorteners_found:
        flags.append(f"URL shortener(s) in redirect chain: {', '.join(shorteners_found)}")

    # ── Risk score from redirect analysis ──
    risk_score = 0.0
    risk_score += min(total_hops * 0.06, 0.30)      # max 0.30 from hop count
    risk_score += domain_changes * 0.10               # 0.10 per domain change
    risk_score += len(meta_hops) * 0.15               # 0.15 per meta-refresh
    risk_score += len(js_hops) * 0.15                 # 0.15 per JS redirect
    risk_score += len(shorteners_found) * 0.05        # 0.05 per shortener
    if orig_scheme == "https" and final_scheme == "http":
        risk_score += 0.15
    if orig_tld != final_tld:
        risk_score += 0.10
    risk_score = round(min(risk_score, 1.0), 2)

    # ── Summary ──
    if not flags:
        summary = "Clean redirect chain – no suspicious patterns detected."
    elif risk_score >= 0.50:
        summary = (
            f"HIGH RISK redirect chain: {total_hops} hop(s) across "
            f"{len(domains_visited)} domain(s). {len(flags)} issue(s) detected."
        )
    else:
        summary = (
            f"Moderate redirect chain: {total_hops} hop(s), "
            f"{len(flags)} minor issue(s) noted."
        )

    return {
        "total_hops": total_hops,
        "domain_changes": domain_changes,
        "domains_visited": domains_visited,
        "flags": flags,
        "risk_score": risk_score,
        "summary": summary,
    }
