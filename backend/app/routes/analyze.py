from fastapi import APIRouter
from app.schemas import ScanRequest, ScanResponse
from app.services.redirect_service import expand_url
from app.services.heuristics import heuristic_score
from app.services.gsb_service import gsb_check
from app.ai.inference import ai_score

router = APIRouter()


@router.post("/analyze", response_model=ScanResponse)
async def analyze_qr(data: ScanRequest):
    content = data.content.strip()
    print("ANALYZE CALLED WITH:", repr(content))

    # 🧼 0. CLEAN QR CONTENT (CRITICAL)
    # Pandas Series accident
    if "dtype:" in content:
        content = content.split()[1]

    # Phishing obfuscation
    content = content.replace("[.]", ".")
    content = content.replace("hxxp://", "http://")
    content = content.replace("hxxps://", "https://")

    # 1. Reject non-web QR codes
    if not content.lower().startswith(("http://", "https://")):
        return {
            "final_url": content,
            "verdict": "NON_WEB_QR",
            "score": 0.0,
            "reasons": ["QR code does not contain a web URL"],
        }

    # 2. Expand redirects (security-aware)
    try:
        final_url = await expand_url(content)
    except Exception as e:
        print("REDIRECT ERROR:", repr(e))
        return {
            "final_url": content,
            "verdict": "SUSPICIOUS",
            "score": 0.9,
            "reasons": [
                "Domain could not be resolved",
                "Obfuscated or fake-looking URL",
            ],
        }

    # 3. Google Safe Browsing
    try:
        gsb_hit = await gsb_check(final_url)
    except Exception as e:
        print("GSB ERROR:", repr(e))
        gsb_hit = False

    if gsb_hit:
        return {
            "final_url": final_url,
            "verdict": "DANGEROUS",
            "score": 1.0,
            "reasons": ["Blocked by Google Safe Browsing"],
        }

    # 4. Heuristics
    h_score, h_reasons = heuristic_score(final_url)

    # 5. AI score
    try:
        ml_prob = ai_score(final_url)
    except Exception as e:
        print("AI ERROR:", repr(e))
        ml_prob = 0.0

    # 6. Verdict logic
    if ml_prob > 0.85 or h_score >= 4:
        verdict = "DANGEROUS"
    elif ml_prob > 0.6 or h_score >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "final_url": final_url,
        "verdict": verdict,
        "score": float(ml_prob),
        "reasons": h_reasons + [f"AI confidence {ml_prob:.2f}"],
    }