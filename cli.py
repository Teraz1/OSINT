#!/usr/bin/env python3
"""
cli.py — Command-line interface for the OSINT & Vulnerability System.

Usage:
  python3 cli.py scan --target domain.com --modules dns,nmap,nuclei
  python3 cli.py scan --target user@email.com --modules email_valid,hibp
  python3 cli.py scan --target domain.com --recommended
  python3 cli.py targets list
  python3 cli.py targets add --target domain.com --label "My Site"
  python3 cli.py report --scan-id abc123 --format pdf
  python3 cli.py tools check
"""

import argparse
import asyncio
import json
import sys
import uuid
from datetime import datetime

# Ensure we can import project modules
sys.path.insert(0, ".")

from config import load_config, check_tools
from modules.registry import MODULE_REGISTRY, RECOMMENDED
from modules.runners import detect_input_type
from orchestrator import run_scan


def color(text, code):
    return f"\033[{code}m{text}\033[0m"

def red(t):    return color(t, "91")
def green(t):  return color(t, "92")
def yellow(t): return color(t, "93")
def cyan(t):   return color(t, "96")
def bold(t):   return color(t, "1")
def dim(t):    return color(t, "2")


def print_banner():
    print(cyan("""
  ╔══════════════════════════════════════════╗
  ║   OSINT & VULNERABILITY SYSTEM — CLI     ║
  ╚══════════════════════════════════════════╝"""))


def cmd_tools_check(args):
    print(bold("\n[Tools Check]"))
    status = check_tools()
    for name, info in status.items():
        if info["available"]:
            print(f"  {green('✓')} {name:<16} {dim(info['path'])}")
        else:
            print(f"  {red('✗')} {name:<16} {dim('NOT FOUND')} — required for: {', '.join(info['required_for'])}")
    print()


def cmd_modules_list(args):
    print(bold("\n[Available Modules]"))
    current_cat = ""
    for key, mod in MODULE_REGISTRY.items():
        if mod["category"] != current_cat:
            current_cat = mod["category"]
            print(f"\n  {yellow(current_cat)}")
        print(f"    {cyan(key):<20} {mod['label']:<30} {dim(', '.join(mod['inputs']))} [{mod['weight']}]")
    print()


async def _run_scan(target: str, modules: list):
    scan_id = str(uuid.uuid4())[:8]
    input_type = detect_input_type(target)
    print(f"\n  {cyan('Target:')}     {target}")
    print(f"  {cyan('Type:')}       {input_type}")
    print(f"  {cyan('Modules:')}    {', '.join(modules)}")
    print(f"  {cyan('Scan ID:')}    {scan_id}\n")

    def progress(step, pct):
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  [{bar}] {pct:3d}%  {step:<50}", end="", flush=True)

    results = await run_scan(target, modules, scan_id, progress_callback=progress)
    print("\n")

    risk = results.get("risk", {})
    risk_color = red if risk.get("level") in ["CRITICAL","HIGH"] else yellow if risk.get("level") == "MEDIUM" else green
    print(f"  {bold('Risk:')} {risk_color(risk.get('level','?'))} ({risk.get('score',0)}/100)")
    for f in risk.get("factors", []):
        print(f"    {dim('▸')} {f}")

    # Summary
    print(f"\n  {bold('Summary:')}")
    if results.get("nmap", {}).get("ports"):
        print(f"    Ports:       {len(results['nmap']['ports'])} open")
    if results.get("nuclei", {}).get("vulnerabilities"):
        print(f"    Nuclei:      {len(results['nuclei']['vulnerabilities'])} findings")
    if results.get("cve", {}).get("cves"):
        print(f"    CVEs:        {len(results['cve']['cves'])} matched")
    if results.get("all_subdomains"):
        print(f"    Subdomains:  {len(results['all_subdomains'])}")
    if results.get("hibp", {}).get("pwned"):
        print(f"    Breaches:    {red(str(results['hibp']['breach_count']) + ' found')}")
    if results.get("pwned_pass", {}).get("pwned"):
        print(f"    Password:    {red('COMPROMISED')}")

    # Save JSON
    out_path = f"data/cli_scan_{scan_id}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  {green('✓')} Results saved: {out_path}")

    # PDF?
    try:
        from reports.pdf_report import generate_pdf
        pdf_path = generate_pdf(scan_id, results)
        print(f"  {green('✓')} PDF report:    {pdf_path}")
    except Exception as e:
        print(f"  {yellow('!')} PDF not generated: {e}")

    print()
    return results


def cmd_scan(args):
    check_tools()

    if not args.target:
        print(red("Error: --target is required"))
        sys.exit(1)

    target = args.target.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    input_type = detect_input_type(target)

    if args.recommended:
        modules = RECOMMENDED.get(input_type, [])
        print(f"  Using recommended modules for {input_type}: {', '.join(modules)}")
    elif args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    else:
        print(red("Error: specify --modules or use --recommended"))
        sys.exit(1)

    asyncio.run(_run_scan(target, modules))


def main():
    print_banner()
    load_config()

    parser = argparse.ArgumentParser(prog="osint-cli", description="OSINT & Vulnerability System CLI")
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Run a scan")
    scan_p.add_argument("--target", "-t", help="Target (domain, IP, email, hash, username, password)")
    scan_p.add_argument("--modules", "-m", help="Comma-separated module list: dns,nmap,nuclei")
    scan_p.add_argument("--recommended", "-r", action="store_true", help="Use recommended modules for input type")
    scan_p.set_defaults(func=cmd_scan)

    # modules
    mod_p = sub.add_parser("modules", help="List available modules")
    mod_p.set_defaults(func=cmd_modules_list)

    # tools
    tools_p = sub.add_parser("tools", help="Check tool availability")
    tools_p.add_argument("check", nargs="?")
    tools_p.set_defaults(func=cmd_tools_check)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
