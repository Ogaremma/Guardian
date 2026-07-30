def detect_sql_injection(text):
    """
    Detect possible SQL Injection attacks.
    """

    patterns = [
        "' OR 1=1",
        '" OR 1=1',
        "UNION SELECT",
        "DROP TABLE",
        "--",
        ";",
        "INSERT INTO",
        "DELETE FROM",
        "UPDATE ",
        "SELECT "
    ]

    text = text.upper()

    for pattern in patterns:

        if pattern.upper() in text:
            return True

    return False