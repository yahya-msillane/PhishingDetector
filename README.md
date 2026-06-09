# 🛡️ Phishing Detector - Android App

Android application that detects phishing attempts in SMS messages and URLs using URL analysis, NLP features, and ML classification.

## ✨ Features

- **Manual Analysis** – Paste any SMS, email, or URL for instant phishing detection
- **Threat Score** – 0-100 risk score with color-coded progress bar
- **Alert Dialogs** – Automatic warnings for medium/high risk content
- **History Log** – Saves last 50 analyses with timestamps
- **HTML Report** – Generates detailed report from 500+ dataset messages

## 🏗️ Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Java |
| Framework | Android SDK (min API 21) |
| URL Analysis | Regex + pattern matching (20+ features) |
| ML Engine | Custom logistic regression (28 features) |
| Reporting | HTML generation |

## 📊 Dataset

500 labeled SMS/email messages (250 phishing + 250 safe) including:
- Brand spoofing (PayPal, Amazon, Netflix)
- Suspicious TLDs (.xyz, .tk, .ga)
- Urgency/threat keywords
- OTP verification code requests

## 📁 Project Structure
PhishingDetector/
├── MainActivity.java # UI + analysis + history
├── ReportGenerator.java # CSV parsing + HTML report
├── UrlAnalyzer.java # URL feature extraction
├── PhishingMLClassifier.java # ML scoring (28 features)
├── phishing_dataset.csv # 500 labeled messages
└── activity_main.xml # App layout

## 🚀 Installation

```bash
git clone https://github.com/yahya-msillane/PhishingDetector
Open in Android Studio → Build → Run on device/emulator (min API 21)

📱 How to Use
Analyze a message – Paste text → Tap ANALYZE → View threat score

Generate report – Tap REPORT → Analyzes 500+ messages → Opens HTML report

📈 Performance
Metric	Value
Accuracy	93.6%
Precision	91.2%
Recall	94.7%
F1-Score	92.9%
👨‍💻 Author
MSILLANE YAHYA – GESTION D'INTRUSION – [28/05/2026]

---