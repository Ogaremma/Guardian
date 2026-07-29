from app.rules.xss import detect_xss

def inspect_request(username, password):
    if detect_xss(username):
        return {
            "safe": False,
            "reason": "Possible XSS attack",
            "severity": "high"
        }
    return {
        "safe": True,
        "reason": "No suspicious activity detected",
        "severity": "None"
    }