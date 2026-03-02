"""
backend.py — Main FastAPI application.
All routes: auth, scans, targets, schedules, findings, reports, graph data.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import sqlalchemy as sa
from fastapi import (BackgroundTasks, Cookie, Depends, FastAPI, HTTPException,
                     Request, Response)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
from auth import get_current_user, log_audit
from config import check_tools, get, load_config
from database import (AsyncSessionLocal, AuditLog, FindingNote, Scan,
                      Schedule, Target, User, init_db)
from modules.registry import ALL_MODULES, MODULE_REGISTRY, RECOMMENDED
from modules.runners import detect_input_type
from notifications import notify_scan_complete
from orchestrator import diff_scans, run_scan
from scheduler import scheduler_loop

# ── use modules/registry.py ALL_MODULES alias ──
try:
    from modules.registry import MODULE_REGISTRY as ALL_MODULES
except:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("backend")

load_config()
TOOL_STATUS = check_tools()

app = FastAPI(title="OSINT & Vulnerability System", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

Path("static").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)


# ── STARTUP ──────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await init_db()
    await auth.create_default_admin()
    asyncio.ensure_future(scheduler_loop())
    logger.info("System ready.")
    logger.info(f"Tools: {', '.join(k for k,v in TOOL_STATUS.items() if v['available'])}")
    unavailable = [k for k,v in TOOL_STATUS.items() if not v["available"]]
    if unavailable:
        logger.warning(f"Unavailable tools: {', '.join(unavailable)}")


# ── STATIC / INDEX ────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    f = Path("static/index.html")
    if f.exists():
        return HTMLResponse(f.read_text())
    return HTMLResponse("<h1>Place index.html in /static/</h1>")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    f = Path("static/login.html")
    if f.exists():
        return HTMLResponse(f.read_text())
    return HTMLResponse("<h1>Place login.html in /static/</h1>")


# ── AUTH ROUTES ───────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    async with AsyncSessionLocal() as db:
        result = await db.execute(sa.select(User).where(User.username == req.username))
        user = result.scalar_one_or_none()

        if not user or not user.active:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Check lockout
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise HTTPException(status_code=429, detail=f"Account locked until {user.locked_until}")

        if not auth.verify_password(req.password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= get("security.max_login_attempts", 5):
                user.locked_until = datetime.utcnow() + timedelta(minutes=get("security.lockout_minutes", 15))
            await db.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        await db.commit()

        token = auth.create_session(user.id, user.username, user.role)
        await log_audit(db, user.id, user.username, "LOGIN",
                        ip=request.client.host if request.client else "")

        response.set_cookie("session", token, httponly=True,
                            max_age=get("server.session_expire_hours", 24) * 3600)
        return {"username": user.username, "role": user.role}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session")
    if token:
        auth.invalidate_session(token)
    response.delete_cookie("session")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@app.post("/api/auth/change-password")
async def change_password(req: ChangePasswordRequest, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        u = await db.get(User, user["user_id"])
        if not auth.verify_password(req.old_password, u.password_hash):
            raise HTTPException(status_code=400, detail="Old password incorrect")
        u.password_hash = auth.hash_password(req.new_password)
        await db.commit()
    return {"ok": True}


# ── MODULE INFO ───────────────────────────────────────────────

@app.get("/api/modules")
async def get_modules():
    result = {}
    for key, mod in MODULE_REGISTRY.items():
        result[key] = {**mod, "tool_available": True}
        req_tool = mod.get("requires_tool")
        if req_tool:
            result[key]["tool_available"] = TOOL_STATUS.get(req_tool, {}).get("available", False)
    return result


@app.get("/api/tools")
async def get_tool_status():
    return TOOL_STATUS


@app.post("/api/detect-type")
async def detect_type(body: dict):
    return {"input_type": detect_input_type(body.get("value", "").strip())}


@app.get("/api/recommended")
async def get_recommended():
    return RECOMMENDED


# ── TARGETS ───────────────────────────────────────────────────

class TargetCreate(BaseModel):
    value: str
    label: str = ""
    tags: List[str] = []
    notes: str = ""

class TargetUpdate(BaseModel):
    label: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None

@app.get("/api/targets")
async def list_targets(user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(sa.select(Target).order_by(Target.created_at.desc()))
        targets = result.scalars().all()
        return [{"id": t.id, "value": t.value, "input_type": t.input_type,
                 "label": t.label, "tags": json.loads(t.tags or "[]"),
                 "notes": t.notes, "last_scanned": t.last_scanned.isoformat() if t.last_scanned else None}
                for t in targets]


@app.post("/api/targets")
async def create_target(req: TargetCreate, user=Depends(get_current_user)):
    value = req.value.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    input_type = detect_input_type(value)
    async with AsyncSessionLocal() as db:
        target = Target(value=value, input_type=input_type, label=req.label,
                        tags=json.dumps(req.tags), notes=req.notes, owner_id=user["user_id"])
        db.add(target)
        await db.commit()
        await db.refresh(target)
        return {"id": target.id, "value": target.value, "input_type": input_type}


@app.patch("/api/targets/{target_id}")
async def update_target(target_id: int, req: TargetUpdate, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        target = await db.get(Target, target_id)
        if not target:
            raise HTTPException(404, "Target not found")
        if req.label is not None:  target.label = req.label
        if req.tags is not None:   target.tags = json.dumps(req.tags)
        if req.notes is not None:  target.notes = req.notes
        await db.commit()
        return {"ok": True}


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        target = await db.get(Target, target_id)
        if not target:
            raise HTTPException(404, "Target not found")
        await db.delete(target)
        await db.commit()
    return {"deleted": target_id}


# ── SCANS ─────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    modules: List[str]
    target_id: Optional[int] = None

async def execute_scan(scan_id: str):
    """Background scan runner — used by both API and scheduler."""
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        await db.commit()

    def progress_cb(step: str, pct: int):
        asyncio.ensure_future(_update_scan_progress(scan_id, step, pct))

    try:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            modules = json.loads(scan.modules)
            target = scan.target_value

        results = await run_scan(target, modules, scan_id, progress_callback=progress_cb)

        # Compute diff vs previous scan of same target
        diff = None
        async with AsyncSessionLocal() as db:
            prev = await db.execute(
                sa.select(Scan).where(
                    Scan.target_value == target,
                    Scan.id != scan_id,
                    Scan.status == "done",
                ).order_by(Scan.created_at.desc()).limit(1)
            )
            prev_scan = prev.scalar_one_or_none()
            if prev_scan and prev_scan.results:
                try:
                    diff = diff_scans(json.loads(prev_scan.results), results)
                except:
                    diff = None

        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            scan.status = "done"
            scan.progress = 100
            scan.step = "Complete"
            scan.results = json.dumps(results)
            scan.diff = json.dumps(diff) if diff else None
            scan.risk_level = results.get("risk", {}).get("level")
            scan.risk_score = results.get("risk", {}).get("score")
            scan.completed_at = datetime.utcnow()
            # Update target last_scanned
            if scan.target_id:
                target_rec = await db.get(Target, scan.target_id)
                if target_rec:
                    target_rec.last_scanned = datetime.utcnow()
            await db.commit()

        # Notify if needed
        await notify_scan_complete(scan_id, target, results, diff)

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.step = f"Error: {str(e)[:200]}"
                await db.commit()


async def _update_scan_progress(scan_id: str, step: str, pct: int):
    try:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.progress = pct
                scan.step = step
                await db.commit()
    except:
        pass


@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks,
                     user=Depends(get_current_user)):
    target = req.target.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    if not target:
        raise HTTPException(400, "Target required")
    if not req.modules:
        raise HTTPException(400, "Select at least one module")

    scan_id = str(uuid.uuid4())[:8]
    input_type = detect_input_type(target)

    async with AsyncSessionLocal() as db:
        scan = Scan(id=scan_id, target_value=target, target_id=req.target_id,
                    input_type=input_type, modules=json.dumps(req.modules),
                    status="pending", step="Queued", owner_id=user["user_id"])
        db.add(scan)
        await db.commit()
        await log_audit(db, user["user_id"], user["username"], "SCAN_START",
                        detail=f"target={target} modules={req.modules}")

    background_tasks.add_task(execute_scan, scan_id)
    return {"scan_id": scan_id, "target": target, "input_type": input_type}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return {"scan_id": scan.id, "target": scan.target_value, "status": scan.status,
                "progress": scan.progress, "step": scan.step,
                "created_at": scan.created_at.isoformat() if scan.created_at else None}


@app.get("/api/scan/{scan_id}/results")
async def scan_results(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "Not found")
        if scan.status != "done":
            return JSONResponse({"status": scan.status, "step": scan.step, "progress": scan.progress})
        return JSONResponse(json.loads(scan.results))


@app.get("/api/scan/{scan_id}/diff")
async def scan_diff(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or not scan.diff:
            return {"has_changes": False}
        return json.loads(scan.diff)


@app.get("/api/scan/{scan_id}/graph")
async def scan_graph(scan_id: str, user=Depends(get_current_user)):
    """Return D3-compatible node/link graph data for the scan."""
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or not scan.results:
            raise HTTPException(404, "No results")
        results = json.loads(scan.results)
    return _build_graph(results)


def _build_graph(results: dict) -> dict:
    nodes, links = [], []
    nid = {}  # label -> id

    def add_node(label: str, type_: str, severity: str = "info", meta: dict = None):
        if label in nid:
            return nid[label]
        node_id = len(nodes)
        nodes.append({"id": node_id, "label": label, "type": type_,
                      "severity": severity, "meta": meta or {}})
        nid[label] = node_id
        return node_id

    def add_link(src_label: str, tgt_label: str, rel: str = ""):
        links.append({"source": nid.get(src_label, 0),
                      "target": nid.get(tgt_label, 0), "rel": rel})

    target = results.get("target", "")
    add_node(target, "target", "root")

    # DNS
    for rtype, vals in results.get("dns", {}).get("records", {}).items():
        for v in (vals or [])[:5]:
            nid_ = add_node(v, "dns_record", "info", {"rtype": rtype})
            add_link(target, v, rtype)

    # Subdomains
    for sub in results.get("all_subdomains", [])[:30]:
        add_node(sub, "subdomain", "info")
        add_link(target, sub, "subdomain")

    # Ports
    for p in results.get("nmap", {}).get("ports", []):
        label = f":{p['port']}/{p.get('service','')}"
        sev = "medium" if p["port"] in {21,22,23,25,3389,5900} else "info"
        add_node(label, "port", sev, p)
        add_link(target, label, "open_port")

    # Vulnerabilities
    for v in results.get("nuclei", {}).get("vulnerabilities", [])[:15]:
        label = v.get("template_id", "")
        add_node(label, "vuln", v.get("severity", "info"), v)
        # Link to matching port if possible
        add_link(target, label, "vulnerability")

    # CVEs
    for c in results.get("cve", {}).get("cves", [])[:10]:
        cve_label = c.get("cve_id", "")
        port_label = f":{c.get('port','')}/{c.get('service','')}"
        add_node(cve_label, "cve", c.get("severity","info").lower(), c)
        if port_label in nid:
            add_link(port_label, cve_label, "cve")
        else:
            add_link(target, cve_label, "cve")

    # Emails
    for email in results.get("harvester", {}).get("emails", [])[:10]:
        add_node(email, "email", "info")
        add_link(target, email, "email")

    return {"nodes": nodes, "links": links}


@app.get("/api/scans")
async def list_scans(limit: int = 50, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            sa.select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        )
        return [
            {"scan_id": s.id, "target": s.target_value, "input_type": s.input_type,
             "modules": json.loads(s.modules), "status": s.status,
             "progress": s.progress, "step": s.step, "risk_level": s.risk_level,
             "risk_score": s.risk_score, "triggered_by": s.triggered_by,
             "created_at": s.created_at.isoformat() if s.created_at else None,
             "completed_at": s.completed_at.isoformat() if s.completed_at else None}
            for s in result.scalars().all()
        ]


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "Not found")
        await db.delete(scan)
        await db.commit()
    return {"deleted": scan_id}


# ── REPORTS ───────────────────────────────────────────────────

@app.get("/api/scan/{scan_id}/report/json")
async def report_json(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or not scan.results:
            raise HTTPException(404, "No results")
        path = Path("reports") / f"report_{scan_id}.json"
        path.write_text(json.dumps(json.loads(scan.results), indent=2))
        return FileResponse(str(path), filename=f"osint_{scan.target_value}_{scan_id}.json")


@app.get("/api/scan/{scan_id}/report/pdf")
async def report_pdf(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or not scan.results:
            raise HTTPException(404, "No results")
        results = json.loads(scan.results)
    try:
        from reports.pdf_report import generate_pdf
        pdf_path = generate_pdf(scan_id, results)
        return FileResponse(pdf_path, filename=f"osint_report_{scan.target_value}_{scan_id}.pdf",
                            media_type="application/pdf")
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {e}")


# ── SCHEDULES ─────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    target_id: int
    modules: List[str]
    interval_hours: int = 24
    notify_on_change: bool = True

@app.get("/api/schedules")
async def list_schedules(user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(sa.select(Schedule).order_by(Schedule.created_at.desc()))
        schedules = result.scalars().all()
        out = []
        for s in schedules:
            target = await db.get(Target, s.target_id)
            out.append({
                "id": s.id, "target_id": s.target_id,
                "target_value": target.value if target else "?",
                "modules": json.loads(s.modules), "interval_hours": s.interval_hours,
                "enabled": s.enabled, "last_run": s.last_run.isoformat() if s.last_run else None,
                "next_run": s.next_run.isoformat() if s.next_run else None,
                "notify_on_change": s.notify_on_change,
            })
        return out


@app.post("/api/schedules")
async def create_schedule(req: ScheduleCreate, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        target = await db.get(Target, req.target_id)
        if not target:
            raise HTTPException(404, "Target not found")
        from datetime import timedelta
        schedule = Schedule(
            target_id=req.target_id, modules=json.dumps(req.modules),
            interval_hours=req.interval_hours, enabled=True,
            next_run=datetime.utcnow(),  # run immediately on first schedule
            notify_on_change=req.notify_on_change,
            created_by=user["user_id"],
        )
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)
        return {"id": schedule.id}


@app.patch("/api/schedules/{schedule_id}")
async def toggle_schedule(schedule_id: int, body: dict, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        schedule = await db.get(Schedule, schedule_id)
        if not schedule:
            raise HTTPException(404, "Not found")
        if "enabled" in body:
            schedule.enabled = body["enabled"]
        await db.commit()
    return {"ok": True}


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        s = await db.get(Schedule, schedule_id)
        if not s: raise HTTPException(404)
        await db.delete(s)
        await db.commit()
    return {"deleted": schedule_id}


# ── FINDING NOTES ─────────────────────────────────────────────

class NoteCreate(BaseModel):
    scan_id: str
    finding_key: str
    status: str = "open"
    note: str = ""

@app.post("/api/findings/note")
async def create_note(req: NoteCreate, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        existing = await db.execute(
            sa.select(FindingNote).where(
                FindingNote.scan_id == req.scan_id,
                FindingNote.finding_key == req.finding_key
            )
        )
        note = existing.scalar_one_or_none()
        if note:
            note.status = req.status
            note.note = req.note
            note.updated_at = datetime.utcnow()
            note.owner_id = user["user_id"]
        else:
            note = FindingNote(scan_id=req.scan_id, finding_key=req.finding_key,
                               status=req.status, note=req.note, owner_id=user["user_id"])
            db.add(note)
        await db.commit()
    return {"ok": True}


@app.get("/api/findings/{scan_id}")
async def get_notes(scan_id: str, user=Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            sa.select(FindingNote).where(FindingNote.scan_id == scan_id)
        )
        notes = result.scalars().all()
        return {n.finding_key: {"status": n.status, "note": n.note,
                                 "updated_at": n.updated_at.isoformat()} for n in notes}


# ── AUDIT LOG ─────────────────────────────────────────────────

@app.get("/api/audit")
async def audit_log(limit: int = 100, user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin only")
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            sa.select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
        )
        return [{"id": e.id, "username": e.username, "action": e.action,
                 "detail": e.detail, "ip": e.ip_address,
                 "timestamp": e.timestamp.isoformat()} for e in result.scalars().all()]


if __name__ == "__main__":
    import uvicorn
    print("""
    ╔══════════════════════════════════════════════╗
    ║   OSINT & Vulnerability System v3.0          ║
    ║   http://localhost:8080                      ║
    ║   Default login: admin / admin123            ║
    ╚══════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host=get("server.host","0.0.0.0"),
                port=get("server.port", 8080), log_level="info")
