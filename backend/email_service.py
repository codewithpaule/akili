"""Transactional email — SMTP with safe async dispatch."""

import logging
import os
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("akili.email")

SMTP_HOST = (os.getenv("SMTP_HOST", "") or "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = (os.getenv("SMTP_USER", "") or "").strip()
SMTP_PASSWORD = (os.getenv("SMTP_PASSWORD", "") or "").strip()
EMAIL_FROM = (os.getenv("EMAIL_FROM", "") or os.getenv("CONTACT_EMAIL", "noreply@akili.io")).strip()
EMAIL_FROM_NAME = (os.getenv("EMAIL_FROM_NAME", "AKILI") or "AKILI").strip()
FRONTEND_URL = (os.getenv("FRONTEND_URL", "http://localhost:5501") or "").rstrip("/")
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "true").strip().lower() in ("1", "true", "yes")
EMAIL_PROVIDER = (os.getenv("EMAIL_PROVIDER", "smtp") or "smtp").strip().lower()
SENDGRID_API_KEY = (os.getenv("SENDGRID_API_KEY", "") or "").strip()


def email_configured() -> bool:
    if not EMAIL_ENABLED:
        return False
    if EMAIL_PROVIDER == "sendgrid":
        return bool(SENDGRID_API_KEY)
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def _send_sendgrid(to: str, subject: str, html_body: str, text_body: str) -> bool:
    import requests
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": EMAIL_FROM, "name": EMAIL_FROM_NAME},
            "subject": subject,
            "content": [
                {"type": "text/plain", "value": text_body or "AKILI"},
                {"type": "text/html", "value": html_body},
            ],
        },
        timeout=30,
    )
    if resp.status_code not in (200, 202):
        logger.error("sendgrid_failed status=%s body=%s", resp.status_code, resp.text[:300])
        return False
    return True


def _send_sync(to: str, subject: str, html_body: str, text_body: str = "") -> bool:
    if not email_configured():
        logger.info("email_skipped to=%s subject=%s (email not configured)", to, subject)
        return False
    if EMAIL_PROVIDER == "sendgrid":
        try:
            ok = _send_sendgrid(to, subject, html_body, text_body)
            if ok:
                logger.info("email_sent_sendgrid to=%s subject=%s", to, subject)
            return ok
        except Exception as e:
            logger.error("sendgrid_error to=%s error=%s", to, e)
            return False
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{EMAIL_FROM_NAME} <{EMAIL_FROM}>"
    msg["To"] = to
    plain = text_body or "View this message in an HTML-capable email client."
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            if SMTP_PORT != 25:
                server.starttls()
                server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [to], msg.as_string())
        logger.info("email_sent to=%s subject=%s", to, subject)
        return True
    except Exception as e:
        logger.error("email_failed to=%s error=%s", to, e)
        return False


def send_email_async(to: str, subject: str, html_body: str, text_body: str = "") -> None:
    """Fire-and-forget so API responses are not blocked by SMTP."""
    t = threading.Thread(target=_send_sync, args=(to, subject, html_body, text_body), daemon=True)
    t.start()


def send_welcome(email: str, name: str) -> None:
    from email_templates import welcome_email
    subject, html = welcome_email(name, FRONTEND_URL)
    send_email_async(email, subject, html, f"Welcome to AKILI, {name or 'there'}. Open {FRONTEND_URL}/dashboard.html")


def send_payment_success(email: str, name: str, plan_id: str, amount_ngn: int) -> None:
    from email_templates import payment_success_email
    subject, html = payment_success_email(name, FRONTEND_URL, plan_id, amount_ngn)
    send_email_async(
        email,
        subject,
        html,
        f"Premium active. Amount: ₦{amount_ngn:,}/month. Dashboard: {FRONTEND_URL}/dashboard.html",
    )


def send_renewal_reminder(email: str, name: str, days_left: int, renew_date: str) -> None:
    from email_templates import renewal_reminder_email
    subject, html = renewal_reminder_email(name, FRONTEND_URL, days_left, renew_date)
    send_email_async(email, subject, html, f"Premium renews in {days_left} days on {renew_date}.")


def send_password_reset(email: str, name: str, reset_token: str) -> None:
    from email_templates import password_reset_email
    link = f"{FRONTEND_URL}/reset-password.html?token={reset_token}"
    subject, html = password_reset_email(name, FRONTEND_URL, link)
    send_email_async(email, subject, html, f"Reset password: {link}")


def send_email_verification(email: str, name: str, verify_token: str) -> None:
    from email_templates import email_verify_email
    link = f"{FRONTEND_URL}/verify-email.html?token={verify_token}"
    subject, html = email_verify_email(name, FRONTEND_URL, link)
    send_email_async(email, subject, html, f"Verify email: {link}")


def send_admin_otp(email: str, name: str, otp: str, minutes: int = 10) -> None:
    from email_templates import admin_otp_email
    subject, html = admin_otp_email(name, FRONTEND_URL, otp, minutes)
    send_email_async(email, subject, html, f"Your admin OTP: {otp} (valid {minutes} minutes)")
