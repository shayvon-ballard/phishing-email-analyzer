import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.header_parser import parse_headers, check_sender, check_subject
from analyzer.url_checker import extract_urls, check_urls
from analyzer.scorer import calculate_risk_score, analyze_email

# --- Route Tests ---

def test_homepage_loads(client):
    response = client.get("/")
    assert response.status_code == 200

def test_404_for_unknown_route(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404

# --- Header Parser Tests ---

def test_parse_headers():
    raw = "From: test@example.com\nSubject: Hello"
    headers = parse_headers(raw)
    assert headers["From"] == "test@example.com"
    assert headers["Subject"] == "Hello"

def test_suspicious_domain_flagged():
    headers = {"From": "attacker@mailinator.com", "Reply-To": "", "Return-Path": ""}
    flags = check_sender(headers)
    assert any("mailinator.com" in f for f in flags)

def test_clean_sender_not_flagged():
    headers = {"From": "hello@gmail.com", "Reply-To": "", "Return-Path": ""}
    flags = check_sender(headers)
    assert len(flags) == 0

def test_reply_to_mismatch_flagged():
    headers = {
        "From": "support@paypal.com",
        "Reply-To": "harvest@evil.com",
        "Return-Path": ""
    }
    flags = check_sender(headers)
    assert any("Reply-To" in f for f in flags)

def test_urgent_subject_flagged():
    headers = {"Subject": "Urgent: Your account has been suspended"}
    flags = check_subject(headers)
    assert len(flags) > 0

def test_clean_subject_not_flagged():
    headers = {"Subject": "Meeting notes from today"}
    flags = check_subject(headers)
    assert len(flags) == 0

# --- URL Checker Tests ---

def test_extract_urls():
    text = "Click here: http://bit.ly/abc and here: https://example.com"
    urls = extract_urls(text)
    assert len(urls) == 2

def test_suspicious_url_flagged():
    text = "Visit http://bit.ly/free-prize now"
    flags, urls = check_urls(text)
    assert len(flags) > 0

def test_clean_url_not_flagged():
    text = "Visit https://anthropic.com for more info"
    flags, urls = check_urls(text)
    assert len(flags) == 0

# --- Scorer Tests ---

def test_high_risk_score():
    score, level = calculate_risk_score(["flag1", "flag2", "flag3"], ["url1", "url2"])
    assert level == "HIGH"

def test_low_risk_score():
    score, level = calculate_risk_score([], [])
    assert score == 0
    assert level == "LOW"

def test_score_capped_at_100():
    score, level = calculate_risk_score(["f"] * 10, ["u"] * 10)
    assert score == 100