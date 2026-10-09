"""
ml_classifier.py – Lightweight ML-based URL maliciousness scorer.

Uses a feature-extraction + Logistic Regression pipeline.
If a trained model is found at  ml_model/url_classifier.pkl  it is loaded;
otherwise a rule-based fallback is used.

Features extracted:
  • URL length
  • Hostname length
  • Number of dots in hostname
  • Number of slashes in path
  • Uses HTTPS (0/1)
  • Has IP as hostname (0/1)
  • Number of special characters
  • Has suspicious TLD (0/1)
  • Path depth
  • Has dangerous extension (0/1)
  • Entropy of URL string
"""

import os
import math
import pickle
import re
from urllib.parse import urlparse

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "url_model.pkl")

_model = None

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".buzz", ".work", ".click", ".link", ".info", ".site",
    ".online", ".icu",
}

DANGEROUS_EXTS = {".apk", ".exe", ".msi", ".bat", ".scr", ".dll"}


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_features(url: str) -> list[float]:
    """Extract numeric features from a URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    is_https = 1.0 if parsed.scheme == "https" else 0.0
    is_ip = 1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0.0
    special_chars = sum(1 for c in url if c in "-_~!$&'()*+,;=:@%")
    sus_tld = 1.0 if any(host.endswith(t) for t in SUSPICIOUS_TLDS) else 0.0
    danger_ext = 1.0 if any(full.endswith(e) for e in DANGEROUS_EXTS) else 0.0

    return [
        float(len(url)),             # 0: url_length
        float(len(host)),            # 1: host_length
        float(host.count(".")),      # 2: num_dots
        float(path.count("/")),      # 3: num_slashes
        is_https,                    # 4: is_https
        is_ip,                       # 5: is_ip
        float(special_chars),        # 6: special_chars
        sus_tld,                     # 7: suspicious_tld
        float(path.count("/")),      # 8: path_depth
        danger_ext,                  # 9: dangerous_ext
        _entropy(url),               # 10: entropy
    ]


def _load_model():
    global _model
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    else:
        _model = None


def predict_url(url: str) -> float | None:
    """
    Return maliciousness probability [0.0, 1.0].
    Returns None if model is not available (fallback heuristic used instead).
    """
    global _model
    if _model is None:
        _load_model()

    features = extract_features(url)

    if _model is not None:
        try:
            proba = _model.predict_proba([features])[0][1]  # P(malicious)
            return round(float(proba), 4)
        except Exception:
            pass

    # ── Fallback: simple weighted rule-based scoring ──
    score = 0.0
    if features[4] == 0:    score += 0.15   # not HTTPS
    if features[5] == 1:    score += 0.20   # IP as host
    if features[7] == 1:    score += 0.15   # suspicious TLD
    if features[9] == 1:    score += 0.25   # dangerous extension
    if features[0] > 150:   score += 0.10   # very long URL
    if features[2] > 4:     score += 0.10   # too many dots
    if features[10] > 4.5:  score += 0.05   # high entropy

    return round(min(score, 1.0), 4)
