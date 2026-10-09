import os
import math
import random
import pickle
import re
from urllib.parse import urlparse

# ── Check for scikit-learn ───────────────────────────────────────────
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
except ImportError:
    print("ERROR: scikit-learn is not installed.")
    print("Run:  pip install scikit-learn")
    exit(1)


# ══════════════════════════════════════════════════════════════════════
# Feature Extraction (same as ml_classifier.py)
# ══════════════════════════════════════════════════════════════════════
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".buzz", ".work", ".click", ".link", ".info", ".site",
    ".online", ".icu",
}

DANGEROUS_EXTS = {".apk", ".exe", ".msi", ".bat", ".scr", ".dll"}


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_features(url: str) -> list[float]:
    """Extract 11 numeric features from a URL."""
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
        shannon_entropy(url),        # 10: entropy
    ]


# ══════════════════════════════════════════════════════════════════════
# Training Data
# ══════════════════════════════════════════════════════════════════════
BENIGN_URLS = [
    "https://www.google.com/search?q=weather",
    "https://www.amazon.in/dp/B09X7Y2",
    "https://en.wikipedia.org/wiki/QR_code",
    "https://github.com/flutter/flutter",
    "https://stackoverflow.com/questions/12345",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://docs.python.org/3/library/re.html",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.flipkart.com/mobiles/pr?sid=tyy",
    "https://example.com/promo?ref=qr",
    "https://www.bbc.com/news",
    "https://www.linkedin.com/in/user",
    "https://twitter.com/user/status/123",
    "https://play.google.com/store/apps/details?id=com.example",
    "https://www.reddit.com/r/programming",
    "https://www.instagram.com/explore/",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone/",
    "https://www.netflix.com/browse",
    "https://www.spotify.com/in-en/",
    "https://www.zomato.com/ahmedabad",
    "https://www.swiggy.com/restaurants",
    "https://www.paytm.com/",
    "https://razorpay.com/docs/",
    "https://www.notion.so/help",
]

MALICIOUS_URLS = [
    "http://192.168.1.50/download.apk",
    "http://xn--pple-43d.com/login",
    "http://10.0.0.1/admin/steal.exe",
    "http://login-verify-secure.tk/paypal/confirm.php",
    "http://www.g00gle.ml/accounts/signin?redirect=steal",
    "http://free-prize-winner.xyz/claim?user=victim",
    "http://192.168.100.5:8080/banking/update.apk",
    "http://secure-update.pw/microsoft/verify/account/login.html",
    "http://amaz0n.click/order/confirm.php",
    "http://sub1.sub2.sub3.sub4.evil.site/phish",
    "http://bit.ly/3XyzPhish",
    "http://malware-download.top/app.msi",
    "http://192.0.2.1/wallet/drain.bat",
    "http://xn--googl-fsa.com/verify",
    "http://banking-secure-login.info/update",
    "http://paypa1-secure.ga/login/verify",
    "http://account-verify.cf/signin",
    "http://172.16.0.1/malware.apk",
    "http://secure-bank-login.buzz/account/update.php",
    "http://free-iphone.icu/claim?id=12345",
    "http://xn--fcebook-8va.com/login",
    "http://192.168.0.100/phish/credentials.exe",
    "http://update-chrome.online/download.apk",
    "http://verify-account.work/login/secure",
    "http://win-prize-now.cc/claim?ref=qr",
]


def generate_dataset() -> tuple[list[list[float]], list[int]]:
    """Generate features and labels from URLs + synthetic variations."""
    X, y = [], []

    # Base URLs
    for url in BENIGN_URLS:
        X.append(extract_features(url))
        y.append(0)

    for url in MALICIOUS_URLS:
        X.append(extract_features(url))
        y.append(1)

    # Generate variations for more training data
    random.seed(42)

    for _ in range(80):
        base = random.choice(BENIGN_URLS)
        suffix = "/" + "".join(random.choices("abcdefghijklmnop", k=random.randint(3, 12)))
        if random.random() > 0.5:
            suffix += "?q=" + "".join(random.choices("abcdef123456", k=random.randint(3, 8)))
        X.append(extract_features(base + suffix))
        y.append(0)

    for _ in range(80):
        base = random.choice(MALICIOUS_URLS)
        suffix = "?" + "".join(random.choices("0123456789abcdef", k=random.randint(5, 15)))
        if random.random() > 0.5:
            suffix += "&token=" + "".join(random.choices("0123456789", k=8))
        X.append(extract_features(base + suffix))
        y.append(1)

    return X, y


# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("  QR Sentinel — ML Model Training")
    print("=" * 60)

    print("\n[1/4] Generating training data...")
    X, y = generate_dataset()
    benign_count = y.count(0)
    malicious_count = y.count(1)
    print(f"       Total samples: {len(X)}")
    print(f"       Benign: {benign_count}  |  Malicious: {malicious_count}")

    print("\n[2/4] Splitting train/test (75/25)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"       Train: {len(X_train)}  |  Test: {len(X_test)}")

    print("\n[3/4] Training Logistic Regression...")
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n── Classification Report ──────────────────────────")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    # Show feature importance
    feature_names = [
        "url_length", "host_length", "num_dots", "num_slashes",
        "is_https", "is_ip", "special_chars", "suspicious_tld",
        "path_depth", "dangerous_ext", "entropy"
    ]
    print("── Feature Weights ────────────────────────────────")
    for name, weight in sorted(zip(feature_names, model.coef_[0]), key=lambda x: abs(x[1]), reverse=True):
        print(f"   {name:20s}  {weight:+.4f}")

    # Test some example URLs
    print("\n── Example Predictions ────────────────────────────")
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.50/download.apk",
        "http://xn--pple-43d.com/login",
        "https://github.com/flutter",
        "http://free-prize.xyz/claim",
    ]
    for url in test_urls:
        features = extract_features(url)
        prob = model.predict_proba([features])[0][1]
        label = "MALICIOUS" if prob >= 0.5 else "SAFE"
        print(f"   {url:45s}  → {prob:.1%} ({label})")

    # Save model
    print("\n[4/4] Saving model...")
    os.makedirs("models", exist_ok=True)
    model_path = os.path.join("models", "url_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print(f"       Saved to: {model_path}")
    print(f"       File size: {os.path.getsize(model_path)} bytes")

    print("\n" + "=" * 60)
    print("  Done! Your model is ready at models/url_model.pkl")
    print("=" * 60)


if __name__ == "__main__":
    main()