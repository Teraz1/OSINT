"""
notifications.py — Email and Slack alerts when critical findings are detected.
"""

import asyncio
import json
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiohttp

from config import get

logger = logging.getLogger("notifications")


def _should_notify(results: dict) -> tuple[bool, list]:
    """Check if scan results contain findings that warrant a notification."""
    trigger_severities = set(get("notifications.email.on_severity", ["critical", "high"]))
    findings = []

    for v in results.get("nuclei", {}).get("vulnerabilities", []):
        if v.get("severity", "").lower() in trigger_severities:
            findings.append(f"[Nuclei] {v.get('name','?')} ({v.get('severity','?').upper()}) — {v.get('matched_url','')}")

    for c in results.get("cve", {}).get("cves", []):
        if c.get("severity", "").upper() in [s.upper() for s in trigger_severities]:
            findings.append(f"[CVE] {c.get('cve_id','?')} CVSS {c.get('cvss_score','?')} — Port {c.get('port','?')}")

    hibp = results.get("hibp", {})
    if hibp.get("pwned") and "breach" in " ".join(get("notifications.email.on_severity", [])).lower():
        findings.append(f"[HIBP] Found in {hibp.get('breach_count',0)} breach(es)")

    return bool(findings), findings


async def notify_scan_complete(scan_id: str, target: str, results: dict, diff: dict = None):
    """Send notifications if findings meet the severity threshold."""
    should_notify, findings = _should_notify(results)
    if not should_notify:
        return

    risk = results.get("risk", {})
    subject = f"[OSINT Alert] {risk.get('level','?')} risk findings on {target}"
    body_lines = [
        f"Scan ID: {scan_id}",
        f"Target:  {target}",
        f"Risk:    {risk.get('level','?')} ({risk.get('score',0)}/100)",
        "",
        "Critical/High Findings:",
    ]
    body_lines += [f"  • {f}" for f in findings]

    if diff and diff.get("has_changes"):
        body_lines += ["", "Changes from previous scan:"]
        if diff.get("new_subdomains"):
            body_lines.append(f"  + {len(diff['new_subdomains'])} new subdomains")
        if diff.get("new_ports"):
            body_lines.append(f"  + New ports: {diff['new_ports']}")
        if diff.get("new_vulns"):
            body_lines.append(f"  + New vulnerabilities: {diff['new_vulns']}")

    body = "\n".join(body_lines)

    # Run notifications concurrently
    tasks = []
    if get("notifications.email.enabled", False):
        tasks.append(_send_email(subject, body))
    if get("notifications.slack.enabled", False):
        tasks.append(_send_slack(subject, findings, risk, target))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"Notifications sent for scan {scan_id}")


async def _send_email(subject: str, body: str):
    cfg = get("notifications.email", {})
    try:
        loop = asyncio.get_event_loop()
        def _send():
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = cfg.get("from_addr", "")
            to_addrs = cfg.get("to_addrs", [])
            msg["To"] = ", ".join(to_addrs)
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP(cfg.get("smtp_host", ""), cfg.get("smtp_port", 587)) as server:
                server.starttls()
                server.login(cfg.get("smtp_user", ""), cfg.get("smtp_pass", ""))
                server.sendmail(cfg.get("from_addr", ""), to_addrs, msg.as_string())
        await loop.run_in_executor(None, _send)
        logger.info("Email notification sent")
    except Exception as e:
        logger.error(f"Email notification failed: {e}")


async def _send_slack(subject: str, findings: list, risk: dict, target: str):
    webhook = get("notifications.slack.webhook_url", "")
    if not webhook:
        return
    color = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffd60a", "LOW": "#30d158"}.get(
        risk.get("level", ""), "#888888"
    )
    payload = {
        "attachments": [{
            "color": color,
            "title": subject,
            "fields": [
                {"title": "Target", "value": target, "short": True},
                {"title": "Risk Score", "value": f"{risk.get('score',0)}/100", "short": True},
                {"title": "Findings", "value": "\n".join(f"• {f}" for f in findings[:10]), "short": False},
            ],
            "footer": "OSINT System",
        }]
    }
    try:
        async with aiohttp.ClientSession() as s:
            await s.post(webhook, json=payload, timeout=aiohttp.ClientTimeout(total=10))
        logger.info("Slack notification sent")
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")
