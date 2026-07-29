from app.rules.xss import detect_xss
from app.rules.bruteforce import detect_bruteforce

def inspect_request(username, password, ip_address):
    if detect_xss(username):
        return {
            "safe": False,
            "reason": "Possible XSS attack",
            "severity": "high"
        }
    if detect_bruteforce(ip_address):
        return {
            "safe": False,
            "reason": "Possible brute force attack",
            "severity": "critical"
        }
    return {
        "safe": True,
        "reason": "No suspicious activity detected",
        "severity": "None"
    }

