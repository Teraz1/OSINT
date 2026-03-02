"""
orchestrator.py — Smart scan runner.
- Light input types (email/password/hash/username): run inline, zero background services
- Heavy input types (domain/ip): use Celery queue if enabled, else async inline
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

from modules.registry import MODULE_REGISTRY, LIGHT_MODULES, HEAVY_MODULES
from modules.runners import dispatch, detect_input_type
from config import get, tool_available

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

RISKY_PORTS = {21, 22, 23, 25, 53, 110, 143, 389, 445, 3389, 5900, 6379, 27017, 9200, 9042, 8080, 8443}


# ── RISK SCORER ──────────────────────────────────────────────

def calculate_risk(results: dict) -> dict:
    score, factors = 0, []

    cves = results.get("cve", {}).get("cves", [])
    crit_cves = [c for c in cves if c.get("severity") in ["CRITICAL", "HIGH"]]
    if crit_cves:
        score += min(35, len(crit_cves) * 10)
        factors.append(f"{len(crit_cves)} Critical/High CVEs matched")

    vulns = results.get("nuclei", {}).get("vulnerabilities", [])
    crit_v = [v for v in vulns if v.get("severity") in ["critical", "high"]]
    if crit_v:
        score += min(30, len(crit_v) * 10)
        factors.append(f"{len(crit_v)} Critical/High Nuclei findings")

    ports = results.get("nmap", {}).get("ports", [])
    risky = [p for p in ports if p.get("port") in RISKY_PORTS]
    if risky:
        score += min(15, len(risky) * 3)
        factors.append(f"{len(risky)} high-risk ports exposed")

    hibp = results.get("hibp", {})
    if hibp.get("pwned"):
        score += 15
        factors.append(f"Email found in {hibp.get('breach_count', 0)} breach(es)")

    pwned = results.get("pwned_pass", {})
    if pwned.get("pwned"):
        score += 25
        factors.append(f"Password compromised ({pwned.get('count', 0):,} exposures)")

    bl = results.get("ip_blacklist", {})
    if bl.get("blacklisted_on"):
        score += min(20, len(bl["blacklisted_on"]) * 7)
        factors.append(f"IP blacklisted on {len(bl['blacklisted_on'])} DNSBL(s)")

    ssl = results.get("ssl_check", {})
    if ssl.get("expired"):
        score += 10
        factors.append("SSL certificate is expired")
    elif ssl.get("expiring_soon"):
        score += 5
        factors.append(f"SSL certificate expires in {ssl.get('days_until_expiry')} days")

    shodan = results.get("shodan", {})
    if shodan.get("vulns"):
        score += min(20, len(shodan["vulns"]) * 5)
        factors.append(f"Shodan reports {len(shodan['vulns'])} known vulnerabilities")

    score = min(100, score)
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    colors = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffd60a", "LOW": "#30d158"}
    return {"score": score, "level": level, "color": colors[level], "factors": factors}


# ── DIFF / CHANGE DETECTION ───────────────────────────────────

def diff_scans(old: dict, new: dict) -> dict:
    """Compare two scan results and return what changed."""
    changes = {
        "new_subdomains": [], "removed_subdomains": [],
        "new_ports": [], "closed_ports": [],
        "new_vulns": [], "resolved_vulns": [],
        "new_cves": [], "risk_change": None,
    }

    old_subs = set(old.get("all_subdomains", []))
    new_subs = set(new.get("all_subdomains", []))
    changes["new_subdomains"] = sorted(new_subs - old_subs)
    changes["removed_subdomains"] = sorted(old_subs - new_subs)

    old_ports = {p["port"] for p in old.get("nmap", {}).get("ports", [])}
    new_ports = {p["port"] for p in new.get("nmap", {}).get("ports", [])}
    changes["new_ports"] = sorted(new_ports - old_ports)
    changes["closed_ports"] = sorted(old_ports - new_ports)

    old_vuln_ids = {v["template_id"] for v in old.get("nuclei", {}).get("vulnerabilities", [])}
    new_vuln_ids = {v["template_id"] for v in new.get("nuclei", {}).get("vulnerabilities", [])}
    changes["new_vulns"] = sorted(new_vuln_ids - old_vuln_ids)
    changes["resolved_vulns"] = sorted(old_vuln_ids - new_vuln_ids)

    old_cve_ids = {c["cve_id"] for c in old.get("cve", {}).get("cves", [])}
    new_cve_ids = {c["cve_id"] for c in new.get("cve", {}).get("cves", [])}
    changes["new_cves"] = sorted(new_cve_ids - old_cve_ids)

    old_risk = old.get("risk", {}).get("level", "")
    new_risk = new.get("risk", {}).get("level", "")
    if old_risk != new_risk:
        changes["risk_change"] = {"from": old_risk, "to": new_risk}

    changes["has_changes"] = any([
        changes["new_subdomains"], changes["removed_subdomains"],
        changes["new_ports"], changes["closed_ports"],
        changes["new_vulns"], changes["new_cves"], changes["risk_change"]
    ])
    return changes


# ── MAIN ORCHESTRATOR ─────────────────────────────────────────

async def run_scan(
    target: str,
    enabled_modules: list,
    scan_id: str,
    progress_callback=None,
) -> dict:
    """
    Smart dispatcher:
    - Detects input type
    - Skips modules incompatible with input type
    - Runs light modules in parallel (no queue overhead)
    - Runs heavy modules sequentially (subprocess tools)
    - CVE lookup runs after nmap (needs port data)
    """
    input_type = detect_input_type(target)

    results = {
        "scan_id": scan_id,
        "target": target,
        "input_type": input_type,
        "timestamp": datetime.utcnow().isoformat(),
        "modules_run": [],
        "modules_skipped": [],
    }

    def cb(step: str, pct: int):
        if progress_callback:
            progress_callback(step, pct)

    cb(f"Input type: {input_type}", 3)

    # Filter modules: only compatible + tool available
    runnable, skipped = [], []
    for key in enabled_modules:
        mod_info = MODULE_REGISTRY.get(key, {})
        if input_type not in mod_info.get("inputs", []):
            skipped.append({"key": key, "reason": f"Not applicable for {input_type}"})
            continue
        req_tool = mod_info.get("requires_tool")
        if req_tool and not tool_available(req_tool):
            skipped.append({"key": key, "reason": f"Tool not installed: {req_tool}"})
            continue
        runnable.append(key)

    results["modules_skipped"] = skipped

    # Separate into light and heavy, and handle CVE specially (needs nmap first)
    light = [k for k in runnable if k in LIGHT_MODULES and k != "cve"]
    heavy_no_cve = [k for k in runnable if k in HEAVY_MODULES]
    has_cve = "cve" in runnable

    total_steps = len(runnable) + (1 if has_cve else 0)
    completed = [0]

    def step_done(key: str, result: dict):
        completed[0] += 1
        pct = 5 + int(completed[0] / max(total_steps, 1) * 90)
        label = MODULE_REGISTRY.get(key, {}).get("label", key)
        cb(f"✓ {label}", pct)
        results[key] = result
        results["modules_run"].append(key)

    # ── Phase 1: All light modules in parallel ──
    if light:
        cb(f"Running {len(light)} lightweight modules...", 8)
        light_results = await asyncio.gather(
            *[dispatch(k, target, results) for k in light],
            return_exceptions=True
        )
        for key, res in zip(light, light_results):
            if isinstance(res, Exception):
                res = {"status": "error", "error": str(res)}
            step_done(key, res)

    # ── Phase 2: Heavy modules sequentially ──
    for key in heavy_no_cve:
        label = MODULE_REGISTRY.get(key, {}).get("label", key)
        cb(f"Running {label}...", 5 + int(completed[0] / max(total_steps, 1) * 90))
        res = await dispatch(key, target, results)
        step_done(key, res)

    # ── Phase 3: CVE lookup (after nmap) ──
    if has_cve:
        cb("Looking up CVEs for detected services...", 88)
        res = await dispatch("cve", target, results)
        step_done("cve", res)

    # ── Merge subdomains from all sources ──
    subs = set()
    for src in ["subfinder", "amass", "crtsh", "harvester"]:
        r = results.get(src, {})
        subs.update(r.get("subdomains", []))
        subs.update(r.get("domains", []))
        subs.update(r.get("hosts", []))
    results["all_subdomains"] = sorted(subs)

    results["risk"] = calculate_risk(results)
    cb("Complete", 100)
    return results
