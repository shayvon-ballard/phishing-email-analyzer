import re

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly",
    r"tinyurl\.com",
    r"t\.co",
    r"goo\.gl",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Raw IP address
    r"@",  # URL with @ symbol (credential harvesting trick)
    r"\.exe",
    r"\.zip",
    r"\.ru",
    r"\.cn",
    r"secure.*login",
    r"verify.*account",
    r"update.*payment",
]

def extract_urls(text):
    url_pattern = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )
    return url_pattern.findall(text)

def check_urls(text):
    flags = []
    urls = extract_urls(text)

    for url in urls:
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flags.append(f"Suspicious URL pattern detected: {url}")
                break

    return flags, urls