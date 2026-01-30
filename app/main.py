from fastapi import FastAPI
from pydantic import BaseModel

from app.rules import rule_based_detector
from app.ai_model import ai_phishing_detector

app = FastAPI(
    title="Phishing Detector API",
    description="Hybrid phishing detection using rules + AI",
    version="1.1"
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


@app.post("/analyze")
def analyze_text(data: TextInput):
    rule_result = rule_based_detector(data.text)
    ai_result = ai_phishing_detector(data.text)

    # weighted fusion
    final_score = round(
        (rule_result["confidence"] * 0.6)
        + (ai_result["confidence"] * 0.4),
        2
    )

    final_verdict = (
        "phishing"
        if final_score >= 0.5
        else "legitimate"
    )

    return {
        "final_verdict": final_verdict,
        "risk_level": risk_level(final_score),
        "final_score": final_score,
        "rule_based": rule_result,
        "ai_based": ai_result
    }
