import re
import httpx
from urllib.parse import urlparse

URL_REGEX = re.compile(r"https?://[^\s]+")

def extract_http_url(text: str) -> str | None:
    if not text:
        return None

    text = text.strip().replace("\n", " ")
    match = URL_REGEX.search(text)
    return match.group(0) if match else None


def is_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


async def expand_url(raw: str) -> str:
    raw = raw.strip()

    url = extract_http_url(raw)

    # 🚫 Non-web QR (UPI, mailto, etc.)
    if not url:
        raise ValueError("QR does not contain a web URL")

    if not is_http_url(url):
        raise ValueError("Non-HTTP scheme detected")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=10
    ) as client:
        response = await client.get(url)
        return str(response.url)