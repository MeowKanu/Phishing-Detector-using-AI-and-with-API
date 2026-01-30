import re
import logging
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel

from app.rules import rule_based_detector
from app.ai_model import ai_phishing_detector

# ---------------- Logging ----------------
logging.basicConfig(
    filename="phishing_detector.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# ---------------- App ----------------
app = FastAPI(
    title="Phishing Detector API",
    description="Hybrid, explainable phishing detection using Rules + AI + URL analysis",
    version="FINAL"
)

# ---------------- Models ----------------
class TextInput(BaseModel):
    text: str

# ---------------- Helpers ----------------
def risk_level(score: float) -> str:
    if score >= 0.75:
        return "high"
    elif score >= 0.4:
        return "medium"
    return "low"


def extract_urls(text: str):
    pattern = r"(https?://[^\s]+)"
    return re.findall(pattern, text.lower())


def analyze_urls(urls):
    suspicious = []

    for url in urls:
        if (
            "bit.ly" in url
            or "tinyurl" in url
            or re.search(r"https?://\d+\.\d+\.\d+\.\d+", url)
            or url.count("-") > 3
            or not url.startswith("https")
        ):
            suspicious.append(url)

    confidence = min(len(suspicious) * 0.3, 1.0)

    return {
        "urls_found": urls,
        "suspicious_urls": suspicious,
        "confidence": round(confidence, 2)
    }

# ---------------- API ----------------
@app.post("/analyze")
def analyze_text(data: TextInput):
    rule_result = rule_based_detector(data.text)
    ai_result = ai_phishing_detector(data.text)

    urls = extract_urls(data.text)
    url_result = analyze_urls(urls)

    final_score = round(
        (rule_result["confidence"] * 0.5)
        + (ai_result["confidence"] * 0.3)
        + (url_result["confidence"] * 0.2),
        2
    )

    final_verdict = "phishing" if final_score >= 0.5 else "legitimate"
    risk = risk_level(final_score)

    explanation = {
        "rule_based": (
            "Matched phishing keywords"
            if rule_result["verdict"] == "phishing"
            else "No critical phishing keywords detected"
        ),
        "ai_based": (
            "Urgent or threatening language detected"
            if ai_result["verdict"] == "phishing"
            else "Language appears normal"
        ),
        "url_based": (
            "Suspicious or obfuscated URLs detected"
            if url_result["confidence"] > 0
            else "No suspicious URLs detected"
        )
    }

    logging.info(
        f"verdict={final_verdict} | risk={risk} | score={final_score} | "
        f"rules={rule_result['confidence']} | ai={ai_result['confidence']} | "
        f"urls={len(urls)}"
    )

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "final_verdict": final_verdict,
        "risk_level": risk,
        "final_score": final_score,
        "explanation": explanation,
        "rule_based": rule_result,
        "ai_based": ai_result,
        "url_analysis": url_result
    }
