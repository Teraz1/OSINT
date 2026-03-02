"""
modules/runners.py — All module implementations.
Light modules: pure async Python, no subprocess.
Heavy modules: subprocess calls to installed tools.
"""

import asyncio
import hashlib
import json
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import aiohttp

from config import get, tool_available

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


# ── UTILITY ──────────────────────────────────────────────────

async def run_cmd(cmd: list, timeout: int = 120):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore"), proc.returncode
    except asyncio.TimeoutError:
        return "", "Timeout", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def _http_session(timeout: int = 10) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers={"User-Agent": "Mozilla/5.0 OSINT-System/2.0"},
        connector=aiohttp.TCPConnector(ssl=False),
    )


# ── INPUT TYPE DETECTOR ──────────────────────────────────────

def detect_input_type(value: str) -> str:
    value = value.strip()
    try:
        socket.inet_aton(value)
        return "ip"
    except:
        pass
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        return "email"
    for length in [32, 40, 56, 64, 96, 128]:
        if re.match(rf"^[a-fA-F0-9]{{{length}}}$", value):
            return "hash"
    if re.match(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", value):
        return "domain"
    if re.match(r"^[a-zA-Z0-9_\-]{3,30}$", value) and "." not in value:
        return "username"
    return "password"


# ══════════════════════════════════════════════════════════════
# LIGHT MODULES (pure async, no subprocess)
# ══════════════════════════════════════════════════════════════

async def run_dns(target: str) -> dict:
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.timeout = 5
        records = {}
        for rtype in ["A", "MX", "NS", "TXT", "CNAME", "AAAA"]:
            try:
                records[rtype] = [str(x) for x in r.resolve(target, rtype)]
            except:
                records[rtype] = []
        return {"status": "ok", "records": records}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_whois(target: str) -> dict:
    try:
        import whois
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, target)
        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]
        return {
            "status": "ok",
            "registrar": str(w.registrar or ""),
            "creation_date": str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "updated_date": str(w.updated_date or ""),
            "name_servers": list(w.name_servers or []),
            "emails": list(set(emails)),
            "org": str(w.org or ""),
            "country": str(w.country or ""),
            "status": str(w.status or ""),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_crtsh(domain: str) -> dict:
    domains = set()
    try:
        async with _http_session(30) as s:
            async with s.get(f"https://crt.sh/?q=%.{domain}&output=json") as resp:
                if resp.status == 200:
                    for entry in await resp.json(content_type=None):
                        for d in entry.get("name_value", "").split("\n"):
                            d = d.strip().lstrip("*.")
                            if d and domain in d:
                                domains.add(d)
    except Exception as e:
        return {"status": "error", "error": str(e)}
    return {"status": "ok", "domains": sorted(domains)}


async def run_ssl_check(target: str) -> dict:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()
        def _get_cert():
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(10)
                s.connect((host, 443))
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
                return cert, cipher, version
        cert, cipher, version = await loop.run_in_executor(None, _get_cert)
        not_after = cert.get("notAfter","")
        not_before = cert.get("notBefore","")
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        # Calculate days until expiry
        days_left = None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.utcnow()).days
            except:
                pass
        return {
            "status": "ok",
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "expired": days_left is not None and days_left < 0,
            "expiring_soon": days_left is not None and 0 <= days_left <= 30,
            "cipher": cipher,
            "tls_version": version,
            "san": [x[1] for x in cert.get("subjectAltName", [])],
        }
    except ssl.SSLCertVerificationError as e:
        return {"status": "warning", "error": f"SSL verification failed: {e}", "host": host}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_cve(ports: list) -> dict:
    all_cves = []
    async with _http_session(15) as s:
        for port in ports:
            service = port.get("service", "")
            if not service or service in ["tcpwrapped", "unknown", ""]:
                continue
            query = f"{service} {port.get('version','')}".strip()
            try:
                async with s.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
                ) as resp:
                    if resp.status == 200:
                        for item in (await resp.json()).get("vulnerabilities", []):
                            cve = item.get("cve", {})
                            metrics = cve.get("metrics", {})
                            score, sev = 0.0, "UNKNOWN"
                            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                m = metrics.get(key, [])
                                if m:
                                    d = m[0].get("cvssData", {})
                                    score = d.get("baseScore", 0.0)
                                    sev = d.get("baseSeverity", "UNKNOWN")
                                    break
                            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                            all_cves.append({
                                "cve_id": cve.get("id", ""), "service": service,
                                "port": port.get("port"), "cvss_score": score,
                                "severity": sev, "description": desc[:400],
                                "published": cve.get("published", ""),
                            })
                await asyncio.sleep(get("scan.nvd_rate_limit_seconds", 0.6))
            except:
                pass
    all_cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return {"status": "ok", "cves": all_cves}


async def run_hibp(value: str) -> dict:
    api_key = get("api_keys.hibp", "")
    if not api_key:
        return {"status": "error", "error": "HIBP API key not configured in config.yaml (api_keys.hibp)"}
    try:
        async with _http_session(15) as s:
            async with s.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{value}?truncateResponse=false",
                headers={"hibp-api-key": api_key}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"status": "ok", "pwned": True, "breach_count": len(data),
                            "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate"),
                                          "data_classes": b.get("DataClasses", [])} for b in data]}
                elif resp.status == 404:
                    return {"status": "ok", "pwned": False, "breach_count": 0, "breaches": []}
                elif resp.status == 429:
                    return {"status": "error", "error": "HIBP rate limit hit — try again in a moment"}
                else:
                    return {"status": "error", "error": f"HIBP returned HTTP {resp.status}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_email_validate(email: str) -> dict:
    result = {"status": "ok", "email": email, "syntax_valid": False,
              "mx_valid": False, "mx_records": [], "disposable": False}
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return result
    result["syntax_valid"] = True
    domain = email.split("@")[1]
    try:
        import dns.resolver
        mx = [str(r) for r in dns.resolver.resolve(domain, "MX")]
        result["mx_valid"] = bool(mx)
        result["mx_records"] = mx
    except:
        result["mx_valid"] = False
    disposable = {"mailinator.com", "guerrillamail.com", "tempmail.com",
                  "throwaway.email", "yopmail.com", "10minutemail.com",
                  "trashmail.com", "fakeinbox.com", "sharklasers.com"}
    result["disposable"] = domain.lower() in disposable
    return result


async def run_pwned_password(password: str) -> dict:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        async with _http_session(10) as s:
            async with s.get(f"https://api.pwnedpasswords.com/range/{prefix}") as resp:
                if resp.status == 200:
                    for line in (await resp.text()).splitlines():
                        h, count = line.split(":")
                        if h.strip() == suffix:
                            return {"status": "ok", "pwned": True, "count": int(count),
                                    "sha1_prefix": prefix}
                    return {"status": "ok", "pwned": False, "count": 0, "sha1_prefix": prefix}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_hash_identify(hash_val: str) -> dict:
    length = len(hash_val)
    types = {
        32: ["MD5", "NTLM", "MD4"],
        40: ["SHA-1", "MySQL4.1+", "SHA-1(Base64)"],
        56: ["SHA-224", "Haval-224"],
        64: ["SHA-256", "BLAKE2s-256", "Haval-256"],
        96: ["SHA-384"],
        128: ["SHA-512", "Whirlpool", "BLAKE2b-512"],
    }
    return {"status": "ok", "hash": hash_val, "length": length,
            "possible_types": types.get(length, ["Unknown — non-standard length"])}


async def run_hash_lookup(hash_val: str) -> dict:
    results = []
    if len(hash_val) == 32:
        try:
            async with _http_session(10) as s:
                async with s.get(f"https://www.nitrxgen.net/md5db/{hash_val}") as resp:
                    text = (await resp.text()).strip()
                    if text and len(text) < 100:
                        results.append({"source": "nitrxgen", "plaintext": text})
        except:
            pass
    return {"status": "ok", "hash": hash_val, "results": results,
            "note": "Free reversal limited to MD5. Paid APIs (CrackStation, MD5Decrypt) needed for full coverage."}


async def run_ip_geo(ip: str) -> dict:
    try:
        async with _http_session(10) as s:
            async with s.get(f"https://ipinfo.io/{ip}/json") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    return {"status": "ok", "ip": d.get("ip"), "hostname": d.get("hostname", ""),
                            "city": d.get("city", ""), "region": d.get("region", ""),
                            "country": d.get("country", ""), "org": d.get("org", ""),
                            "timezone": d.get("timezone", ""), "loc": d.get("loc", "")}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_ip_asn(ip: str) -> dict:
    try:
        async with _http_session(10) as s:
            async with s.get(f"https://api.bgpview.io/ip/{ip}") as resp:
                if resp.status == 200:
                    data = (await resp.json()).get("data", {})
                    return {"status": "ok",
                            "asns": [{"asn": p.get("asn", {}).get("asn"),
                                      "name": p.get("asn", {}).get("name"),
                                      "prefix": p.get("prefix")}
                                     for p in data.get("prefixes", [])],
                            "rir": data.get("rir_allocation", {})}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_ip_blacklist(ip: str) -> dict:
    try:
        import dns.resolver
        reversed_ip = ".".join(reversed(ip.split(".")))
        lists = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
                 "b.barracudacentral.org", "dnsbl-1.uceprotect.net"]
        hits = []
        for bl in lists:
            try:
                dns.resolver.resolve(f"{reversed_ip}.{bl}", "A")
                hits.append(bl)
            except:
                pass
        return {"status": "ok", "blacklisted_on": hits,
                "clean": len(hits) == 0, "checked_lists": lists}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_shodan(target: str) -> dict:
    api_key = get("api_keys.shodan", "")
    if not api_key:
        return {"status": "error", "error": "Shodan API key not configured (api_keys.shodan in config.yaml)"}
    try:
        async with _http_session(15) as s:
            # resolve domain to IP if needed
            ip = target
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
                try:
                    ip = socket.gethostbyname(target)
                except:
                    return {"status": "error", "error": f"Could not resolve {target}"}
            async with s.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "status": "ok", "ip": ip,
                        "org": data.get("org", ""),
                        "country": data.get("country_name", ""),
                        "isp": data.get("isp", ""),
                        "os": data.get("os", ""),
                        "ports": data.get("ports", []),
                        "vulns": list(data.get("vulns", {}).keys()),
                        "tags": data.get("tags", []),
                        "last_update": data.get("last_update", ""),
                        "hostnames": data.get("hostnames", []),
                    }
                elif resp.status == 404:
                    return {"status": "ok", "note": "No Shodan data for this IP", "ip": ip}
                else:
                    return {"status": "error", "error": f"Shodan HTTP {resp.status}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_username(username: str) -> dict:
    platforms = {
        "GitHub":     f"https://github.com/{username}",
        "GitLab":     f"https://gitlab.com/{username}",
        "Twitter":    f"https://twitter.com/{username}",
        "Instagram":  f"https://www.instagram.com/{username}",
        "Reddit":     f"https://www.reddit.com/user/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "Dev.to":     f"https://dev.to/{username}",
        "Keybase":    f"https://keybase.io/{username}",
        "Medium":     f"https://medium.com/@{username}",
        "ProductHunt":f"https://www.producthunt.com/@{username}",
    }
    async def check(platform, url):
        try:
            async with _http_session(8) as s:
                async with s.get(url, allow_redirects=True) as resp:
                    return {"platform": platform, "url": url,
                            "exists": resp.status == 200, "status_code": resp.status}
        except:
            return {"platform": platform, "url": url, "exists": None, "status_code": "timeout"}
    results = await asyncio.gather(*[check(p, u) for p, u in platforms.items()])
    found = [r for r in results if r["exists"] is True]
    return {"status": "ok", "username": username, "platforms": list(results), "found_count": len(found)}


async def run_github_secrets(query: str) -> dict:
    """Search GitHub for leaked secrets related to domain/username."""
    try:
        searches = [
            f'"{query}" password', f'"{query}" api_key',
            f'"{query}" secret', f'"{query}" token',
        ]
        results = []
        async with _http_session(10) as s:
            for q in searches[:2]:  # limit to 2 to avoid rate limit
                async with s.get(
                    f"https://api.github.com/search/code?q={q}&per_page=5",
                    headers={"Accept": "application/vnd.github.v3+json"}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("items", []):
                            results.append({
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("path", ""),
                                "url": item.get("html_url", ""),
                                "query": q,
                            })
                    await asyncio.sleep(1)
        return {"status": "ok", "results": results, "note": "Results require manual verification"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ══════════════════════════════════════════════════════════════
# HEAVY MODULES (subprocess)
# ══════════════════════════════════════════════════════════════

async def run_subfinder(domain: str) -> dict:
    t = get("scan.timeouts.subfinder", 120)
    stdout, _, code = await run_cmd(
        [get("tools.subfinder", "subfinder"), "-d", domain, "-silent"], timeout=t
    )
    return {"status": "ok", "subdomains": [s.strip() for s in stdout.splitlines() if s.strip()]}


async def run_amass(domain: str) -> dict:
    t = get("scan.timeouts.amass", 180)
    stdout, _, code = await run_cmd(
        [get("tools.amass", "amass"), "enum", "-passive", "-d", domain], timeout=t
    )
    return {"status": "ok",
            "subdomains": [s.strip() for s in stdout.splitlines() if s.strip() and domain in s]}


async def run_harvester(domain: str) -> dict:
    t = get("scan.timeouts.theharvester", 120)
    out = DATA_DIR / f"harv_{domain.replace('.','_')}"
    harvester_path = get("tools.theharvester", "/opt/theHarvester/theHarvester.py")
    stdout, _, _ = await run_cmd(
        ["python3", harvester_path, "-d", domain,
         "-b", "anubis,certspotter,crtsh,dnsdumpster,hackertarget",
         "-f", str(out)], timeout=t
    )
    emails, hosts = [], []
    json_path = Path(str(out) + ".json")
    if json_path.exists():
        try:
            d = json.loads(json_path.read_text())
            emails, hosts = d.get("emails", []), d.get("hosts", [])
        except:
            pass
    if not emails:
        for line in stdout.splitlines():
            line = line.strip()
            if "@" in line and "." in line:
                emails.append(line)
            elif re.match(r"[\w\-\.]+\." + re.escape(domain), line):
                hosts.append(line)
    return {"status": "ok", "emails": list(set(emails)), "hosts": list(set(hosts))}


async def run_nmap(target: str) -> dict:
    t = get("scan.timeouts.nmap", 180)
    flags = get("scan.nmap_flags", "-sV -sC --open -T4").split()
    stdout, _, code = await run_cmd(
        [get("tools.nmap", "nmap")] + flags + ["-oX", "-", target], timeout=t
    )
    ports = []
    if stdout and code == 0:
        try:
            root = ET.fromstring(stdout)
            for host in root.findall("host"):
                for port in host.findall(".//port"):
                    state = port.find("state")
                    svc = port.find("service")
                    if state is not None and state.get("state") == "open":
                        ports.append({
                            "port": int(port.get("portid")),
                            "protocol": port.get("protocol"),
                            "service": svc.get("name") if svc is not None else "unknown",
                            "version": ((svc.get("product", "") + " " + svc.get("version", "")).strip()) if svc is not None else "",
                            "extra": svc.get("extrainfo", "") if svc is not None else "",
                        })
        except:
            pass
    return {"status": "ok" if code == 0 else "partial", "ports": ports}


async def run_whatweb(target: str) -> dict:
    t = get("scan.timeouts.whatweb", 60)
    url = target if target.startswith("http") else f"http://{target}"
    stdout, _, code = await run_cmd(
        [get("tools.whatweb", "whatweb"), "--log-json=/dev/stdout", url], timeout=t
    )
    technologies = []
    try:
        lines = [l for l in stdout.splitlines() if l.strip().startswith("[")]
        if lines:
            data = json.loads(lines[0])
            if isinstance(data, list):
                for entry in data:
                    for tech, details in entry.get("plugins", {}).items():
                        technologies.append({
                            "name": tech,
                            "version": details.get("version", [""])[0] if details.get("version") else "",
                        })
    except:
        pass
    return {"status": "ok", "technologies": technologies}


async def run_nuclei(target: str) -> dict:
    t = get("scan.timeouts.nuclei", 300)
    sev = get("scan.nuclei_severity", "critical,high,medium")
    url = target if target.startswith("http") else f"http://{target}"
    stdout, _, _ = await run_cmd(
        [get("tools.nuclei", "nuclei"), "-u", url,
         "-severity", sev, "-json", "-silent", "-no-color"], timeout=t
    )
    vulns = []
    for line in stdout.splitlines():
        try:
            data = json.loads(line.strip())
            vulns.append({
                "template_id": data.get("template-id", ""),
                "name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", "unknown"),
                "description": data.get("info", {}).get("description", ""),
                "matched_url": data.get("matched-at", ""),
                "tags": data.get("info", {}).get("tags", []),
                "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score", None),
            })
        except:
            continue
    return {"status": "ok", "vulnerabilities": vulns}


# ── MODULE DISPATCHER ─────────────────────────────────────────

async def dispatch(key: str, target: str, context: dict) -> dict:
    """Route module key to its runner function."""
    try:
        if key == "dns":           return await run_dns(target)
        elif key == "whois":       return await run_whois(target)
        elif key == "crtsh":       return await run_crtsh(target)
        elif key == "ssl_check":   return await run_ssl_check(target)
        elif key == "subfinder":   return await run_subfinder(target)
        elif key == "amass":       return await run_amass(target)
        elif key == "harvester":   return await run_harvester(target)
        elif key == "nmap":        return await run_nmap(target)
        elif key == "whatweb":     return await run_whatweb(target)
        elif key == "nuclei":      return await run_nuclei(target)
        elif key == "cve":         return await run_cve(context.get("nmap", {}).get("ports", []))
        elif key == "hibp":        return await run_hibp(target)
        elif key == "email_valid": return await run_email_validate(target)
        elif key == "pwned_pass":  return await run_pwned_password(target)
        elif key == "hash_id":     return await run_hash_identify(target)
        elif key == "hash_lookup": return await run_hash_lookup(target)
        elif key == "ip_geo":      return await run_ip_geo(target)
        elif key == "ip_asn":      return await run_ip_asn(target)
        elif key == "ip_blacklist":return await run_ip_blacklist(target)
        elif key == "shodan":      return await run_shodan(target)
        elif key == "username":    return await run_username(target)
        elif key == "github_secrets": return await run_github_secrets(target)
        else:                      return {"status": "error", "error": f"Unknown module: {key}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
