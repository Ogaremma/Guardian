from app.rules.xss import detect_xss
from app.rules.sql import detect_sql_injection
from app.rules.bruteforce import detect_bruteforce


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
    
    if detect_sql_injection(username) or detect_sql_injection(password):
        return {
            "safe": False,
            "reason": "Possible SQL Injection",
            "severity": "High"
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