from app.rules.xss import detect_xss
from app.bruteforce import detect_bruteforce

def run_rules(username, password, ip_address):
    """
    Runs all Guardian detection rules.
    """
    if detect_xss(username):
            return {
                "safe": False,
                "reason": "Possible XSS attack",
                "severity": "high"
            }
    if detect_bruteforce(ip_address):
            return {
                "safe": False,
                "reason": "Possible Brute Force attack",
                "severity": "Critical"
            }
    return {
        "safe": True,
        "reason": "No suspicious activity detected",
        "severity": "None"
    }