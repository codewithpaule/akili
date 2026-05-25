"""HTML email layouts — AKILI brand, blinking eye, prices from pricing catalog."""

from pricing import PLANS


def _logo_svg() -> str:
    return """
    <svg width="48" height="48" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="AKILI">
      <circle cx="16" cy="16" r="14" stroke="#2563EB" stroke-width="2" fill="none"/>
      <circle cx="16" cy="16" r="6" fill="#2563EB"/>
      <circle class="akili-eye" cx="18" cy="14" r="2" fill="#ffffff"/>
    </svg>"""


def _layout(inner_html: str, preheader: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width">
  <meta name="color-scheme" content="light">
  <title>AKILI</title>
  <style>
    @keyframes akili-blink {{
      0%, 42%, 58%, 100% {{ opacity: 1; transform: scaleY(1); }}
      50% {{ opacity: 0.15; transform: scaleY(0.12); }}
    }}
    .akili-eye {{
      animation: akili-blink 2.8s ease-in-out infinite;
      transform-origin: 18px 14px;
    }}
    @media (prefers-reduced-motion: reduce) {{
      .akili-eye {{ animation: none; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
  <span style="display:none;max-height:0;overflow:hidden;mso-hide:all;">{preheader}</span>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" style="max-width:560px;background:#ffffff;border-radius:12px;border:1px solid #e2e8f0;overflow:hidden;">
        <tr><td style="padding:28px 32px 12px;text-align:center;background:linear-gradient(180deg,#eff6ff 0%,#ffffff 100%);">
          {_logo_svg()}
          <p style="margin:12px 0 0;font-size:22px;font-weight:700;color:#0f172a;letter-spacing:0.04em;">AKILI</p>
          <p style="margin:4px 0 0;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.12em;">Intelligence Platform</p>
        </td></tr>
        <tr><td style="padding:8px 32px 32px;color:#334155;font-size:15px;line-height:1.65;">
          {inner_html}
        </td></tr>
        <tr><td style="padding:16px 32px 24px;border-top:1px solid #e2e8f0;font-size:12px;color:#94a3b8;text-align:center;">
          © AKILI · You received this because of activity on your account.<br>
          <a href="{{{{frontend_url}}}}/privacy.html" style="color:#2563EB;">Privacy</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _btn(href: str, label: str) -> str:
    return f"""<p style="text-align:center;margin:28px 0 8px;">
      <a href="{href}" style="display:inline-block;background:#2563EB;color:#ffffff;text-decoration:none;padding:14px 28px;border-radius:8px;font-weight:600;font-size:15px;">{label}</a>
    </p>"""


def _price_block(plan_id: str = "premium_monthly") -> str:
    plan = PLANS.get(plan_id) or PLANS["premium_monthly"]
    ngn = plan.get("price_ngn", 0)
    formatted = f"₦{ngn:,}" if ngn else "Free"
    return f"""<table role="presentation" width="100%" style="margin:20px 0;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;">
      <tr><td style="padding:16px 20px;">
        <p style="margin:0;font-size:13px;color:#64748b;text-transform:uppercase;letter-spacing:0.06em;">{plan.get("name", "Premium")}</p>
        <p style="margin:6px 0 0;font-size:28px;font-weight:700;color:#0f172a;">{formatted}<span style="font-size:14px;font-weight:500;color:#64748b;">/month</span></p>
        <p style="margin:8px 0 0;font-size:13px;color:#475569;">{plan.get("description", "")}</p>
      </td></tr>
    </table>"""


def welcome_email(name: str, frontend_url: str) -> tuple[str, str]:
    display = name or "there"
    body = _layout(
        f"""<h1 style="margin:0 0 12px;font-size:22px;color:#0f172a;">Welcome to AKILI, {display}</h1>
        <p>Your account is ready. You have a <strong>14-day trial</strong> with full access to intelligence modules, API keys, and the sandbox.</p>
        <ul style="padding-left:1.2rem;color:#475569;">
          <li>Website, vulnerability, OSINT &amp; domain scans</li>
          <li>Dashboard usage tracking</li>
          <li>Shareable reports</li>
        </ul>
        {_btn(f"{frontend_url}/dashboard.html", "Open dashboard")}
        <p style="font-size:13px;color:#64748b;">After trial, contact the administrator for extended usage. Billing and paid plans are disabled on this deployment.</p>""",
        preheader="Your AKILI trial has started — 14 days of full access.",
    )
    return f"Welcome to AKILI — your trial has started", body.replace("{{frontend_url}}", frontend_url.rstrip("/"))


def payment_success_email(name: str, frontend_url: str, plan_id: str, amount_ngn: int) -> tuple[str, str]:
    plan = PLANS.get(plan_id) or PLANS["premium_monthly"]
    expected = int(plan.get("price_ngn") or 0)
    if amount_ngn != expected and expected > 0:
        amount_ngn = expected
    formatted = f"₦{amount_ngn:,}"
    # Billing disabled — return a generic confirmation stub for compatibility.
    body = _layout(
      f"""<h1 style=\"margin:0 0 12px;font-size:22px;color:#0f172a;\">Payment processed</h1>
      <p>Hi {name or "there"}, billing is disabled on this deployment; this message is informational only.</p>
      """,
      preheader="Payment processed",
    )
    return "AKILI — payment processed (disabled)", body.replace("{{frontend_url}}", frontend_url.rstrip("/"))


def renewal_reminder_email(name: str, frontend_url: str, days_left: int, renew_date: str) -> tuple[str, str]:
    body = _layout(
      f"""<h1 style=\"margin:0 0 12px;font-size:22px;color:#0f172a;\">Subscription reminder</h1>
      <p>Hi {name or "there"}, billing and subscriptions are disabled on this deployment.</p>
      """,
      preheader=f"Subscription notice",
    )
    return "AKILI — subscription notice", body.replace("{{frontend_url}}", frontend_url.rstrip("/"))


def email_verify_email(name: str, frontend_url: str, verify_link: str) -> tuple[str, str]:
    body = _layout(
        f"""<h1 style="margin:0 0 12px;font-size:22px;color:#0f172a;">Verify your email</h1>
        <p>Hi {name or "there"}, confirm your email to secure your AKILI account and receive billing notices.</p>
        {_btn(verify_link, "Verify email")}
        <p style="font-size:13px;color:#64748b;">Link expires in 48 hours.</p>
        """,
        preheader="Confirm your AKILI email address",
    )
    return "AKILI — verify your email", body.replace("{{frontend_url}}", frontend_url.rstrip("/"))


def password_reset_email(name: str, frontend_url: str, reset_link: str) -> tuple[str, str]:
    body = _layout(
        f"""<h1 style="margin:0 0 12px;font-size:22px;color:#0f172a;">Reset your password</h1>
        <p>Hi {name or "there"}, we received a request to reset your AKILI password. This link expires in <strong>1 hour</strong>.</p>
        {_btn(reset_link, "Reset password")}
        <p style="font-size:13px;color:#64748b;word-break:break-all;">Or copy: {reset_link}</p>
        <p style="font-size:13px;color:#64748b;">If you did not request this, ignore this email — your password will not change.</p>
        """,
        preheader="Reset your AKILI password",
    )
    return "AKILI — password reset", body.replace("{{frontend_url}}", frontend_url.rstrip("/"))
