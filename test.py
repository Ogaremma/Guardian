from app.alerts import send_alert

send_alert(
    recipient_email="emmawills725@gmail.com",
    website="Local Guardian",
    attack_type="SQL Injection",
    severity="High",
    source_ip="127.0.0.1",
    username="admin' OR 1=1"
)