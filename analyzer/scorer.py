def calculate_risk_score(header_flags, url_flags):
    score = 0

    # Each header flag adds 25 points
    score += len(header_flags) * 25

    # Each URL flag adds 20 points
    score += len(url_flags) * 20

    # Cap at 100
    score = min(score, 100)

    if score >= 75:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level


def analyze_email(raw_email):
    from analyzer.header_parser import parse_headers, check_sender, check_subject
    from analyzer.url_checker import check_urls

    headers = parse_headers(raw_email)
    header_flags = check_sender(headers) + check_subject(headers)
    url_flags, urls = check_urls(raw_email)

    score, risk_level = calculate_risk_score(header_flags, url_flags)

    return {
        "headers": headers,
        "header_flags": header_flags,
        "url_flags": url_flags,
        "urls": urls,
        "score": score,
        "risk_level": risk_level
    }