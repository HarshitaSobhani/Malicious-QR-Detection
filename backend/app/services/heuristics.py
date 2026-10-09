import re
from urllib.parse import urlparse

def heuristic_score(url: str):
    score = 0
    reasons = []

    host = urlparse(url).hostname or ""

    if host.startswith("xn--"):
        score += 2
        reasons.append("Punycode domain detected")

    if re.match(r"\d+\.\d+\.\d+\.\d+", host):
        score += 2
        reasons.append("IP-based URL detected")

    if len(host.split(".")) > 4:
        score += 1
        reasons.append("Excessive subdomains")

    if url.endswith((".apk", ".exe", ".zip")):
        score += 3
        reasons.append("Suspicious download file")

    return score, reasons