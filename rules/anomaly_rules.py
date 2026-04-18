def detect_abnormal_input(data):
    """
    Detect abnormal or malicious input patterns.
    """

    if len(data) > 50:
        return "MEDIUM", "Abnormal input size detected"

    if "<script>" in data:
        return "HIGH", "XSS attempt detected"

    if "OR 1=1" in data or "--" in data:
        return "HIGH", "SQL Injection attempt detected"

    return "INFO", "Normal input"
