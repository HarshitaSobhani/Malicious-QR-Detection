from pydantic import BaseModel
from typing import List, Optional


class ScanRequest(BaseModel):
    content: str


class ScanResponse(BaseModel):
    final_url: Optional[str] = None
    verdict: str
    score: float
    reasons: List[str]