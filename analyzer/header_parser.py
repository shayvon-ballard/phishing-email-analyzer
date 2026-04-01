import re

SUSPICIOUS_DOMAINS = [
    "mailinator.com", "tempmail.com", "guerrillamail.com",
    "10minutemail.com", "throwaway.email", "yopmail.com"
]

def parse_headers(raw_email):
    headers = {}
    lines = raw_email.strip().split("\n")
    
    for line in lines:
        if ": " in line:
            key, _, value = line.partition(": ")
            headers[key.strip()] = value.strip()
    
    return headers

def check_sender(headers):
    flags = []
    
    from_field = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")

    for domain in SUSPICIOUS_DOMAINS:
        if domain in from_field.lower():
            flags.append(f"Suspicious sender domain detected: {domain}")

    if reply_to and from_field:
        from_domain = re.search(r"@([\w.]+)", from_field)
        reply_domain = re.search(r"@([\w.]+)", reply_to)
        if from_domain and reply_domain:
            if from_domain.group(1) != reply_domain.group(1):
                flags.append(f"Reply-To domain mismatch: From={from_domain.group(1)} Reply-To={reply_domain.group(1)}")

    if return_path and from_field:
        from_domain = re.search(r"@([\w.]+)", from_field)
        return_domain = re.search(r"@([\w.]+)", return_path)
        if from_domain and return_domain:
            if from_domain.group(1) != return_domain.group(1):
                flags.append(f"Return-Path domain mismatch: From={from_domain.group(1)} Return-Path={return_domain.group(1)}")

    return flags

def check_subject(headers):
    flags = []
    subject = headers.get("Subject", "").lower()

    URGENT_KEYWORDS = [
        "urgent", "immediate action", "account suspended", "verify your account", "click here", "limited time",
        "you have been selected", "congratulations", "winner",
        "password expired", "unusual activity"
    ]

    for keyword in URGENT_KEYWORDS:
        if keyword in subject:
            flags.append(f"Suspicious subject keyword: '{keyword}'")

    return flags