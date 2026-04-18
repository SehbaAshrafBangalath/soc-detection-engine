def detect_bruteforce(fail_count):
    if fail_count >= 10:
        return "CRITICAL", "Brute Force Attack Detected"
    elif fail_count >= 5:
        return "HIGH", "Suspicious Login Activity"
    else:
        return "INFO", "Normal Activity"
