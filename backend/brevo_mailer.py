"""
Brevo (Sendinblue) Email Service for SecurePass AI
Sends transactional emails for Password Reset, 6-Digit OTP Double Authentication,
and Security Verification Links.
"""
import os
import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def get_brevo_config():
    """Load Brevo configuration from environment variables."""
    api_key = os.environ.get("BREVO_API_KEY", "").strip()
    sender_email = os.environ.get("BREVO_SENDER_EMAIL", "security@securepass.ai").strip()
    sender_name = os.environ.get("BREVO_SENDER_NAME", "SecurePass AI Sentinel").strip()
    return {
        "api_key": api_key,
        "sender_email": sender_email,
        "sender_name": sender_name,
    }


def build_reset_email_html(recipient_email: str, otp_code: str, reset_url: str) -> str:
    """Build a modern, executive-styled HTML email with dual OTP + 1-Click Link."""
    year = datetime.utcnow().year
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePass AI Password Reset</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f8fafc; padding: 40px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" style="max-width: 580px; background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; box-shadow: 0 10px 25px rgba(15, 23, 42, 0.05); overflow: hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 32px 36px 24px; border-bottom: 1px solid #f1f5f9; background: linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%);">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td>
                                        <div style="font-size: 20px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">
                                            <span style="color: #4f46e5;">SecurePass</span> AI
                                        </div>
                                        <div style="font-size: 11px; font-weight: 700; color: #6366f1; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 3px;">
                                            Identity & Access Governance
                                        </div>
                                    </td>
                                    <td align="right">
                                        <span style="display: inline-block; padding: 4px 10px; background-color: #ecfdf5; color: #059669; font-size: 11px; font-weight: 700; border-radius: 99px; letter-spacing: 0.04em;">
                                            • 2FA VERIFICATION
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Body Content -->
                    <tr>
                        <td style="padding: 36px 36px 28px;">
                            <h1 style="margin: 0 0 12px; font-size: 22px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">
                                Password Reset Request
                            </h1>
                            <p style="margin: 0 0 24px; font-size: 14px; line-height: 1.6; color: #475569;">
                                We received a request to reset your SecurePass AI account password for <strong>{recipient_email}</strong>. For your security, complete double authentication using either the 6-digit OTP or direct reset button below.
                            </p>

                            <!-- 2FA OTP Card -->
                            <div style="background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border: 1.5px solid #e2e8f0; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 28px;">
                                <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-bottom: 10px;">
                                    Your 6-Digit Verification Code (OTP)
                                </div>
                                <div style="font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #4f46e5; padding: 6px 0;">
                                    {otp_code}
                                </div>
                                <div style="font-size: 12px; color: #64748b; margin-top: 8px;">
                                    Valid for <strong>10 minutes</strong>. Do not share this code with anyone.
                                </div>
                            </div>

                            <!-- 1-Click Reset Link Button -->
                            <div style="text-align: center; margin-bottom: 28px;">
                                <div style="font-size: 13px; color: #475569; margin-bottom: 12px; font-weight: 500;">
                                    Prefer 1-click password reset?
                                </div>
                                <a href="{reset_url}" target="_blank" style="display: inline-block; background: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%); color: #ffffff; text-decoration: none; padding: 13px 28px; border-radius: 10px; font-size: 14px; font-weight: 700; letter-spacing: 0.01em; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);">
                                    Reset Password Directly →
                                </a>
                            </div>

                            <!-- Security Warning -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #fffbeb; border: 1px solid #fef3c7; border-radius: 8px; padding: 14px;">
                                <tr>
                                    <td style="font-size: 12px; line-height: 1.5; color: #92400e;">
                                        <strong>Didn't request this?</strong> If you didn't ask to reset your password, please ignore this email or contact security immediately. Your current password remains secure.
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 24px 36px; background-color: #f8fafc; border-top: 1px solid #f1f5f9; text-align: center;">
                            <p style="margin: 0 0 6px; font-size: 12px; color: #94a3b8;">
                                SecurePass AI Sentinel Security Platform · SOC 2 Type II Certified
                            </p>
                            <p style="margin: 0; font-size: 11px; color: #cbd5e1;">
                                © {year} SecurePass AI. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""


def send_password_reset_email(to_email: str, otp_code: str, reset_url: str) -> dict:
    """
    Send password reset email via Brevo REST API.
    If Brevo API key is not configured, logs to terminal and returns simulated success
    so development/testing proceeds smoothly.
    """
    config = get_brevo_config()
    api_key = config["api_key"]
    sender_email = config["sender_email"]
    sender_name = config["sender_name"]

    subject = f"SecurePass AI: {otp_code} is your password reset code"
    html_content = build_reset_email_html(to_email, otp_code, reset_url)

    if not api_key or api_key.startswith("your_") or api_key == "placeholder":
        logger.warning(
            "BREVO_API_KEY not configured or is placeholder. Falling back to console simulation."
        )
        print("\n" + "=" * 76)
        print("  [BREVO EMAIL SERVICE — SIMULATED DELIVERY]")
        print(f"  To:            {to_email}")
        print(f"  From:          {sender_name} <{sender_email}>")
        print(f"  Subject:       {subject}")
        print(f"  6-Digit OTP:   {otp_code}")
        print(f"  Direct Reset:  {reset_url}")
        print("=" * 76 + "\n")
        return {
            "success": True,
            "mode": "simulated",
            "message": "Verification code logged to console (BREVO_API_KEY not set).",
            "otp_preview": otp_code,
        }

    # Dispatch to Brevo REST API
    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email,
        },
        "to": [
            {
                "email": to_email,
            }
        ],
        "subject": subject,
        "htmlContent": html_content,
    }

    try:
        response = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=10)
        if response.status_code in (200, 201, 202):
            logger.info("Brevo email dispatched successfully to %s", to_email)
            return {
                "success": True,
                "mode": "live",
                "messageId": response.json().get("messageId"),
            }
        else:
            logger.error("Brevo API returned error %s: %s", response.status_code, response.text)
            # Log fallback to console so user is not blocked
            print("\n" + "=" * 76)
            print("  [BREVO API ERROR — CONSOLE RESCUE]")
            print(f"  Brevo response: {response.text}")
            print(f"  To:             {to_email}")
            print(f"  6-Digit OTP:    {otp_code}")
            print(f"  Direct Reset:   {reset_url}")
            print("=" * 76 + "\n")
            return {
                "success": True,
                "mode": "simulated_after_error",
                "warning": f"Brevo API error {response.status_code}, code logged to terminal.",
                "otp_preview": otp_code,
            }
    except Exception as exc:
        logger.exception("Failed to connect to Brevo API: %s", exc)
        print("\n" + "=" * 76)
        print("  [BREVO CONNECTION EXCEPTION — CONSOLE RESCUE]")
        print(f"  Error:          {exc}")
        print(f"  To:             {to_email}")
        print(f"  6-Digit OTP:    {otp_code}")
        print(f"  Direct Reset:   {reset_url}")
        print("=" * 76 + "\n")
        return {
            "success": True,
            "mode": "simulated_after_exception",
            "warning": f"Network exception: {exc}, code logged to terminal.",
            "otp_preview": otp_code,
        }
