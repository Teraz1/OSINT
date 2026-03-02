"""
config.py — Loads and validates config.yaml, checks tool availability at startup.
"""
import shutil
import subprocess
import sys
from pathlib import Path
import yaml

_cfg = None

def load_config(path: str = "config.yaml") -> dict:
    global _cfg
    if _cfg:
        return _cfg
    with open(path) as f:
        _cfg = yaml.safe_load(f)
    return _cfg

def get(path: str, default=None):
    """Dotted path accessor: get('api_keys.hibp')"""
    cfg = load_config()
    parts = path.split(".")
    val = cfg
    for p in parts:
        if not isinstance(val, dict):
            return default
        val = val.get(p, default)
    return val

# ── TOOL AVAILABILITY CHECK ──────────────────────

TOOL_STATUS = {}  # populated at startup

TOOL_REGISTRY = {
    "nmap":          {"key": "tools.nmap",          "required_for": ["domain","ip"]},
    "nuclei":        {"key": "tools.nuclei",         "required_for": ["domain","ip"]},
    "subfinder":     {"key": "tools.subfinder",      "required_for": ["domain"]},
    "amass":         {"key": "tools.amass",          "required_for": ["domain"]},
    "whatweb":       {"key": "tools.whatweb",        "required_for": ["domain","ip"]},
    "theharvester":  {"key": "tools.theharvester",   "required_for": ["domain"]},
}

def check_tools() -> dict:
    """Run at startup. Returns dict of tool -> available bool."""
    global TOOL_STATUS
    for name, info in TOOL_REGISTRY.items():
        path = get(info["key"], name)
        if name == "theharvester":
            available = Path(path).exists()
        else:
            available = shutil.which(path) is not None
        TOOL_STATUS[name] = {
            "available": available,
            "path": path,
            "required_for": info["required_for"],
        }
    return TOOL_STATUS

def tool_available(name: str) -> bool:
    return TOOL_STATUS.get(name, {}).get("available", False)

def available_modules_for_type(input_type: str) -> list:
    """Return list of module keys that are both compatible and have their tools available."""
    from modules.registry import MODULE_REGISTRY
    result = []
    for key, mod in MODULE_REGISTRY.items():
        if input_type not in mod.get("inputs", []):
            continue
        required_tool = mod.get("requires_tool")
        if required_tool and not tool_available(required_tool):
            continue
        result.append(key)
    return result
