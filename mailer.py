"""Send transactional email (verification and password reset) through a free provider.

Set MAIL_PROVIDER to one of:
- resend : MAIL_API_KEY from resend.com (free tier, needs a verified sending domain)
- brevo  : MAIL_API_KEY from brevo.com (free tier, a single verified sender address is enough)
- smtp   : SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS (for example a Gmail app password)
and MAIL_FROM, for example "NextCore BD <no-reply@example.org>".
"""
import os
import smtplib
from email.message import EmailMessage
from email.utils import parseaddr

import httpx


def configured() -> bool:
    p = os.environ.get("MAIL_PROVIDER", "").strip().lower()
    if not os.environ.get("MAIL_FROM", "").strip():
        return False
    if p in ("resend", "brevo"):
        return bool(os.environ.get("MAIL_API_KEY"))
    if p == "smtp":
        return bool(os.environ.get("SMTP_HOST"))
    return False


def send(to: str, subject: str, text: str, html: str = "") -> bool:
    """True when the provider accepted the message. Never raises: callers must not leak failures to users."""
    if not configured():
        return False
    name, addr = parseaddr(os.environ["MAIL_FROM"])
    provider = os.environ["MAIL_PROVIDER"].strip().lower()
    try:
        if provider == "resend":
            r = httpx.post("https://api.resend.com/emails", timeout=15,
                           headers={"Authorization": "Bearer " + os.environ["MAIL_API_KEY"]},
                           json={"from": os.environ["MAIL_FROM"], "to": [to], "subject": subject,
                                 "text": text, **({"html": html} if html else {})})
            return r.status_code < 300
        if provider == "brevo":
            r = httpx.post("https://api.brevo.com/v3/smtp/email", timeout=15,
                           headers={"api-key": os.environ["MAIL_API_KEY"]},
                           json={"sender": {"name": name or addr, "email": addr}, "to": [{"email": to}],
                                 "subject": subject, "textContent": text,
                                 **({"htmlContent": html} if html else {})})
            return r.status_code < 300
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = os.environ["MAIL_FROM"], to, subject
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
            s.send_message(msg)
        return True
    except Exception:
        return False
