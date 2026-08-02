from app.logger import log_attack
from app.database import save_attack
from app.alerts import send_alert

def handle_incident(
    website,
    attack_type,
    severity,
    source_ip,
    username,
    recipient_email
):
    log_attack(
        username,
        attack_type,
        source_ip
    )

    save_attack(
        website,
        attack_type,
        severity,
        source_ip,
        username
    )

    send_alert(
        recipient_email,
        website,
        attack_type,
        severity,
        source_ip,
        username
    )