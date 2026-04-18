def detect_rapid_action(request_count):
    if request_count > 20:
        return "HIGH", "Rapid activity detected (possible bot attack)"
    elif request_count > 10:
        return "MEDIUM", "Elevated request rate detected"
    else:
        return "INFO", "Normal activity"
