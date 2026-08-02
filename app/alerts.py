import smtplib
import os

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from dotenv import load_dotenv


def send_alert(
    recipient_email,
    website,
    attack_type,
    severity,
    source_ip,
    username
):
    load_dotenv()

    sender_email = os.getenv("GUARDIAN_EMAIL")
    sender_password = os.getenv("GUARDIAN_PASSWORD")

    message = MIMEMultipart()

    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = "🚨 GUARDIAN SECURITY ALERTS"

    body = f"""
    🚨 GUARDIAN SECURITY ALERT

    Website: {website}

    Attack Type: {attack_type}

    Severity: {severity}

    IP Address: {source_ip}

    Username Used: {username}

    Recommended Action:
    Review logs immediately.
    """

    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.starttls()

        server.login(sender_email, sender_password)

        server.sendmail(
            sender_email,
            recipient_email,
            message.as_string()
        )

        server.quit()

        print("Email alert sent successfully.")

    except Exception as error:
        print("Failed to send email.")
        print(error)