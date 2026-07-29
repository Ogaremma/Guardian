import time
from app.memory import failed_attempts

MAX_ATTEMPTS = 5
TIME_WINDOW = 60

def detect_bruteforce(ip_address):
    """
    Detect multiple failed login attempts
    from the same IP address.
    """

    current_time = time.time()

    if ip_address not in failed_attempts:
        failed_attempts[ip_address] = []

    failed_attempts