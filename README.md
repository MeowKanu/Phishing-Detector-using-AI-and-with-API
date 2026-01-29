# Phishing Detector using AI and API

## 📖 Overview
This project is a **hybrid phishing detection system** that combines:
- Rule-based (human-defined) phishing detection
- AI-based phishing detection using NLP
- A REST API for real-time analysis

The system is designed to analyze emails or text messages and determine whether they are **phishing or legitimate**, along with a confidence score.

---

## 🎯 Project Objectives
- Detect phishing attempts using heuristic rules
- Enhance detection using AI-based natural language processing
- Expose detection logic via a RESTful API
- Build a modular and extensible security tool

---

## 🧠 Detection Architecture
Input Text
|
|--> Rule-Based Detector
|--> AI-Based NLP Detector
|
|--> Final Decision Engine
|
--> Verdict + Confidence Score


---

## 🛠️ Technologies Used
- Python 3
- FastAPI
- Transformers (NLP)
- PyTorch
- Scikit-learn
- Kali Linux
- GitHub

---

## 📂 Project Structure
Phishing-Detector-using-AI-and-with-API/
├── requirements.txt
└── app/
├── init.py
├── main.py
├── rules.py
└── ai_model.py



---

## 🚀 API Endpoint
### POST `/analyze`

**Request Body**
```json
{
  "text": "Your account is suspended. Verify immediately."
}

Response
{
  "final_verdict": "phishing",
  "final_score": 0.86,
  "rule_based": {...},
  "ai_based": {...}
}


⚠️ Disclaimer

This project is intended for educational and security research purposes only.
