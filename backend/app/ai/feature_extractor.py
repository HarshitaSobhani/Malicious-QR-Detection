from urllib.parse import urlparse
import re

def extract_features(url):
    parsed = urlparse(url)
    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("/"),
        int(parsed.scheme == "https"),
        int(bool(re.search(r"\d", url)))
    ]