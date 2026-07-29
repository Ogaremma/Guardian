def inspect_request(username, password):
    """
    Inspect the incoming login request.
    Returns a dictionary describing whether
    the request looks suspicious.
    """
    if "<script>" in username:
        return {
            "safe": False,
            "reason": "Possible XSS attack detected"
        }
    return {
        "safe": True,
        "reason": "No suspicious activity detected"
    }

