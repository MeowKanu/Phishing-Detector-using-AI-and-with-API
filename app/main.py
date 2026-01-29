# app/main.py

from fastapi import FastAPI
from pydantic import BaseModel

from app.rules import rule_based_detector
from app.ai_model import ai_phishing_detector

app = FastAPI(
    title="Phishing Detector API",
    description="Hybrid phishing detection using rules + AI",
    version="1.0"
)


class TextInput(BaseModel):
    text: str


@app.post("/analyze")
def analyze_text(data: TextInput):
    """
    Analyze text for phishing using rule-based and AI detection
    """

    rule_result = rule_based_detector(data.text)
    ai_result = ai_phishing_detector(data.text)

    # Combine results (simple weighted logic)
    final_score = (
        (rule_result["confidence"] * 0.6)
        + (ai_result["confidence"] * 0.4)
    )

    final_verdict = (
        "phishing" if (
            rule_result["verdict"] == "phishing"
            or ai_result["verdict"] == "phishing"
        )
        else "legitimate"
    )

    return {
        "final_verdict": final_verdict,
        "final_score": round(final_score, 2),
        "rule_based": rule_result,
        "ai_based": ai_result
    }
