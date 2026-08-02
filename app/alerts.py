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