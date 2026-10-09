"""
QR Sentinel – FastAPI Backend (v3)
Enhanced with:
  • Full redirect chain analysis with discrepancy detection
  • WHOIS domain age verification
  • Meta-refresh & JavaScript redirect detection
  • Brand impersonation detection
  • Updated verdict aggregation
  • UPDATED: ANY phish in PhishTank = auto-dangerous (no viral threshold)
"""
import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
load_dotenv()
from .analyzer import full_analysis

app = FastAPI(
    title="QR Sentinel API",
    version="3.0.0",
    description="Smart QR Code Security Scanner",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response models ────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    content: str


class RedirectHop(BaseModel):
    url: str
    status: int
    location: str | None = None
    redirect_type: str | None = None
    error: str | None = None


class RedirectAnalysis(BaseModel):
    total_hops: int = 0
    domain_changes: int = 0
    domains_visited: list[str] = []
    flags: list[str] = []
    risk_score: float = 0.0
    summary: str = ""


class WhoisInfo(BaseModel):
    domain: str = ""
    age_days: int | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    registrar: str | None = None
    flags: list[str] = []
    risk_score: float = 0.0
    whois_available: bool = False
    summary: str = ""


class PhishResult(BaseModel):
    """
    PhishTank result – supports dict format with phish detection.
    UPDATED: is_phish indicates ANY phish (not just viral).
    """
    status: str | None = None
    is_phish: bool = False
    verdict: str | None = None
    recent_reports: int = 0
    valid_reports: int = 0
    phish_detail_page: str = ""


class AnalyzeResponse(BaseModel):
    content_type: str
    raw: str
    final_url: str | None
    redirect_chain: list[RedirectHop]
    redirect_analysis: RedirectAnalysis = RedirectAnalysis()
    whois_info: WhoisInfo = WhoisInfo()
    verdict: str
    score: float
    reasons: list[str]
    gsb_result: str
    phishtank_result: PhishResult | dict
    heuristic_flags: list[str]
    ml_score: float | None
    scanned_at: str


# ── Endpoints ────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    """
    Analyze a QR code for security threats.
    
    UPDATED: Any phish detected in PhishTank = auto-dangerous verdict.
    Returns immediately with verdict="dangerous" and score=1.0.
    
    Args:
        req.content: QR code content (URL, UPI, or text)
    
    Returns:
        AnalyzeResponse with verdict, score, and detailed analysis
    """
    result = await full_analysis(req.content)
    
    # Convert phishtank_result to PhishResult model if it's a dict
    phishtank_result = result.get("phishtank_result")
    if isinstance(phishtank_result, dict):
        # It's already a dict from the updated check_phishtank()
        phishtank_result_model = phishtank_result
    else:
        # Legacy string format - convert to dict
        phishtank_result_model = {
            "status": phishtank_result,
            "is_phish": False,
            "verdict": None,
            "recent_reports": 0,
            "valid_reports": 0,
            "phish_detail_page": "",
        }
    
    # Build response
    response_data = {
        "content_type": result.get("content_type"),
        "raw": result.get("raw"),
        "final_url": result.get("final_url"),
        "redirect_chain": result.get("redirect_chain", []),
        "redirect_analysis": result.get("redirect_analysis", RedirectAnalysis()),
        "whois_info": result.get("whois_info", WhoisInfo()),
        "verdict": result.get("verdict"),
        "score": result.get("score"),
        "reasons": result.get("reasons", []),
        "gsb_result": result.get("gsb_result"),
        "phishtank_result": phishtank_result_model,
        "heuristic_flags": result.get("heuristic_flags", []),
        "ml_score": result.get("ml_score"),
        "scanned_at": result.get("scanned_at"),
    }
    
    return response_data


# ── Dev runner ───────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
