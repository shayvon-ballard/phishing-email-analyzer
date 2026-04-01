# Phishing Email Analyzer 🎣

![CI](https://github.com/shayvon-ballard/phishing-email-analyzer/actions/workflows/test.yml/badge.svg)

A Python-based phishing email analyzer that parses raw email headers, detects suspicious indicators, flags malicious URLs, and assigns a phishing risk score through a Flask web dashboard.

## Screenshots
*(add screenshot here)*

## Features
- Email header parsing and analysis
- Suspicious sender domain detection
- Reply-To and Return-Path mismatch detection
- Urgency keyword analysis in subject lines
- URL extraction and suspicious pattern detection
- Phishing risk scoring (0-100) with HIGH/MEDIUM/LOW classification
- Flask web dashboard for real-time analysis
- CSV export of findings

## Tech Stack
- Python 3
- Flask
- Regex (built-in Python)

## Setup
Clone the repository, create and activate a virtual environment, and install dependencies from requirements.txt.

## Usage
Launch the dashboard with python3 dashboard/app.py and open your browser at http://127.0.0.1:5000. Paste raw email headers and body into the text box and click Analyze.

## Testing
Automated test suite with 14 pytest tests covering:
- Route validation
- Header parsing and sender analysis
- Suspicious domain and keyword detection
- URL extraction and pattern matching
- Risk scoring logic

Run tests:
```bash
python3 -m pytest tests/ -v
```

## Author
ShayVon Ballard
- GitHub: https://github.com/shayvon-ballard