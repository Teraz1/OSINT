"""
modules/registry.py — Single source of truth for every module.
Light modules (email/password/hash/username) run inline (no queue).
Heavy modules (domain/IP) go through Celery queue.
"""

MODULE_REGISTRY = {
    # ── RECON ────────────────────────────────────────
    "dns": {
        "label": "DNS Recon", "category": "Recon",
        "inputs": ["domain"], "weight": "light",
        "requires_tool": None,
        "description": "A/MX/NS/TXT/CNAME records via dnspython",
    },
    "whois": {
        "label": "WHOIS Lookup", "category": "Recon",
        "inputs": ["domain", "ip"], "weight": "light",
        "requires_tool": None,
        "description": "Registrar, creation date, org, emails",
    },
    "crtsh": {
        "label": "Cert Transparency", "category": "Recon",
        "inputs": ["domain"], "weight": "light",
        "requires_tool": None,
        "description": "Subdomains from SSL certificate logs (crt.sh)",
    },
    "subfinder": {
        "label": "Subdomain Enum", "category": "Recon",
        "inputs": ["domain"], "weight": "heavy",
        "requires_tool": "subfinder",
        "description": "50+ passive subdomain sources",
    },
    "amass": {
        "label": "Amass DNS", "category": "Recon",
        "inputs": ["domain"], "weight": "heavy",
        "requires_tool": "amass",
        "description": "Deep passive DNS enumeration",
    },
    "harvester": {
        "label": "Email Harvester", "category": "Recon",
        "inputs": ["domain"], "weight": "heavy",
        "requires_tool": "theharvester",
        "description": "Emails and hosts from OSINT sources",
    },

    # ── ACTIVE ───────────────────────────────────────
    "nmap": {
        "label": "Port Scan (Nmap)", "category": "Active",
        "inputs": ["domain", "ip"], "weight": "heavy",
        "requires_tool": "nmap",
        "description": "Open ports, services, versions",
    },
    "whatweb": {
        "label": "Tech Fingerprint", "category": "Active",
        "inputs": ["domain", "ip"], "weight": "heavy",
        "requires_tool": "whatweb",
        "description": "CMS, frameworks, server software",
    },
    "ssl_check": {
        "label": "SSL/TLS Analyzer", "category": "Active",
        "inputs": ["domain", "ip"], "weight": "light",
        "requires_tool": None,
        "description": "Cert expiry, ciphers, protocol versions",
    },

    # ── VULNERABILITY ────────────────────────────────
    "nuclei": {
        "label": "Vuln Scan (Nuclei)", "category": "Vuln",
        "inputs": ["domain", "ip"], "weight": "heavy",
        "requires_tool": "nuclei",
        "description": "9000+ vulnerability templates",
    },
    "cve": {
        "label": "CVE Lookup (NVD)", "category": "Vuln",
        "inputs": ["domain", "ip"], "weight": "light",
        "requires_tool": None,
        "description": "CVEs matched to detected services via NIST NVD",
    },

    # ── CREDENTIAL ───────────────────────────────────
    "hibp": {
        "label": "Breach Check (HIBP)", "category": "Credential",
        "inputs": ["email", "domain"], "weight": "light",
        "requires_tool": None,
        "description": "Check email/domain against HaveIBeenPwned",
    },
    "email_valid": {
        "label": "Email Validation", "category": "Credential",
        "inputs": ["email"], "weight": "light",
        "requires_tool": None,
        "description": "Syntax, MX record, disposable domain check",
    },
    "pwned_pass": {
        "label": "Password Pwned Check", "category": "Credential",
        "inputs": ["password"], "weight": "light",
        "requires_tool": None,
        "description": "k-anonymity SHA-1 check via HIBP (password never sent)",
    },

    # ── HASH ─────────────────────────────────────────
    "hash_id": {
        "label": "Hash Identifier", "category": "Hash",
        "inputs": ["hash"], "weight": "light",
        "requires_tool": None,
        "description": "Identify hash algorithm by length and charset",
    },
    "hash_lookup": {
        "label": "Hash Lookup", "category": "Hash",
        "inputs": ["hash"], "weight": "light",
        "requires_tool": None,
        "description": "Attempt reversal via free rainbow table APIs",
    },

    # ── IP INTEL ─────────────────────────────────────
    "ip_geo": {
        "label": "IP Geolocation", "category": "IP Intel",
        "inputs": ["ip"], "weight": "light",
        "requires_tool": None,
        "description": "City, country, org, timezone via ipinfo.io",
    },
    "ip_asn": {
        "label": "ASN / BGP Lookup", "category": "IP Intel",
        "inputs": ["ip"], "weight": "light",
        "requires_tool": None,
        "description": "Autonomous system info via BGPView",
    },
    "ip_blacklist": {
        "label": "Blacklist Check", "category": "IP Intel",
        "inputs": ["ip"], "weight": "light",
        "requires_tool": None,
        "description": "DNS blacklist check (Spamhaus, SpamCop, SORBS)",
    },
    "shodan": {
        "label": "Shodan Lookup", "category": "IP Intel",
        "inputs": ["ip", "domain"], "weight": "light",
        "requires_tool": None,
        "description": "Internet exposure data (requires Shodan API key)",
    },

    # ── SOCIAL ───────────────────────────────────────
    "username": {
        "label": "Username OSINT", "category": "Social",
        "inputs": ["username"], "weight": "light",
        "requires_tool": None,
        "description": "Check username on GitHub, Twitter, Reddit, and more",
    },
    "github_secrets": {
        "label": "GitHub Secret Scan", "category": "Social",
        "inputs": ["domain", "username"], "weight": "light",
        "requires_tool": None,
        "description": "Search GitHub for leaked API keys and credentials",
    },
}

# Convenience: modules by weight
LIGHT_MODULES = {k for k,v in MODULE_REGISTRY.items() if v["weight"] == "light"}
HEAVY_MODULES = {k for k,v in MODULE_REGISTRY.items() if v["weight"] == "heavy"}

# Recommended defaults per input type
RECOMMENDED = {
    "domain":   ["dns","whois","crtsh","subfinder","harvester","nmap","whatweb","ssl_check","nuclei","cve"],
    "ip":       ["whois","nmap","whatweb","ssl_check","nuclei","cve","ip_geo","ip_asn","ip_blacklist"],
    "email":    ["email_valid","hibp"],
    "password": ["pwned_pass"],
    "hash":     ["hash_id","hash_lookup"],
    "username": ["username","github_secrets"],
}
