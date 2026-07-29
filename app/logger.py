from datetime import datetime

def log_attack(username, reason):
    """
    Save suspicious activities to a log file.
    """
    with open("logs/access.log", "a") as file:
        file.write(
            f"[{datetime.now()}]"
            f"Username: {username}, |"
            f"Reason: {reason}\n"
        )