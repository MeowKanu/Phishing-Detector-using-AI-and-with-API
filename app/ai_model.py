from transformers import pipeline

classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english"
)


def ai_phishing_detector(text: str) -> dict:
    result = classifier(text)[0]
    label = result["label"]
    score = result["score"]

    phishing_indicators = [
        "urgent",
        "immediately",
        "verify",
        "suspended",
        "click",
        "login",
        "confirm"
    ]

    indicator_hits = sum(
        1 for word in phishing_indicators if word in text.lower()
    )

    if label == "NEGATIVE" and score > 0.80 and indicator_hits >= 1:
        verdict = "phishing"
    else:
        verdict = "legitimate"

    return {
        "verdict": verdict,
        "confidence": round(score, 2),
        "model_label": label,
        "indicator_hits": indicator_hits
    }
