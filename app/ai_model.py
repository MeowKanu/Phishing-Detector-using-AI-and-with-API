# app/ai_model.py

from transformers import pipeline

# Load a pretrained NLP model
# Using a lightweight model suitable for CPU
classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english"
)


def ai_phishing_detector(text: str) -> dict:
    """
    AI-based phishing detection using NLP
    """

    result = classifier(text)[0]

    label = result["label"]
    score = result["score"]

    # Mapping sentiment output to phishing logic
    if label == "NEGATIVE" and score > 0.85:
        verdict = "phishing"
    else:
        verdict = "legitimate"

    return {
        "verdict": verdict,
        "confidence": round(score, 2),
        "model_label": label
    }
