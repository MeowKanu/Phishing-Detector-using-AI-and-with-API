import re
import logging
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel

from app.rules import rule_based_detector
from app.ai_model import ai_phishing_detector

# Logging setup
logging.basicConfig(
    filename="phishing_detector.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

app = FastAPI(
    title="Phishing Detector API",
    description="Explainable hybrid phishing detection using rules, AI, and URL analysis",
    version="1.4"
)


class TextInput(BaseModel):
    text: str


def risk_level(score: float) -> str:
    if score >= 0.75:
        return "high"
    elif score >= 0.4:
        return "medium"
    else:
        return "low"


def extract_urls(text: str):
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text.lower())


def analyze_urls(urls: list) -> dict:
    suspicious = []

    for url in urls:
        if any([
            "bit.ly" in url,
            "tinyurl" in url,
            re.search(r"https?://\d+\.\d+\.\d+\.\d+", url),
            url.count("-") > 3,
            not url.startswith("https")
        ]):
            suspicious.append(url)

    confidence = min(len(suspicious) * 0.3, 1.0)

    return {
        "urls_found": urls,
        "suspicious_urls": suspicious,
        "confidence": round(confidence, 2)
    }


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
        "rule_based_reason": (
            "Matched phishing keywords"
            if rule_result["verdict"] == "phishing"
            else "No critical phishing keywords detected"
        ),
        "ai_reason": (
            "Language shows urgency or threat patterns"
            if ai_result["verdict"] == "phishing"
            else "Language appears normal"
        ),
        "url_reason": (
            "Suspicious or shortened URLs detected"
            if url_result["confidence"] > 0
            else "No suspicious URLs detected"
        )
    }

    logging.info(
        f"verdict={final_verdict} | risk={risk} | score={final_score} | "
        f"explain={explanation}"
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
