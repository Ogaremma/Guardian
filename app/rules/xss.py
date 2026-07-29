def detect_xss(text):
    """
    Detect possible XSS attacks.
    """

    patterns = [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
    ]

    for pattern in patterns:
        if pattern.lower() in text.lower():
            return True
    return False