PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "account suspended",
    "click here",
    "login immediately",
    "update your account",
    "password",
    "confirm identity",
    "security alert"
]


def rule_based_detector(text: str) -> dict:
    text = text.lower()
    score = 0
    matched_keywords = []

    for keyword in PHISHING_KEYWORDS:
        if keyword in text:
            score += 1
            matched_keywords.append(keyword)

    confidence = min(score / len(PHISHING_KEYWORDS), 1.0)
    verdict = "phishing" if score >= 2 else "legitimate"

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "matched_keywords": matched_keywords
    }
