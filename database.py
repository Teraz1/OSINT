"""
database.py — All SQLAlchemy models and DB setup.
Tables: users, targets, scans, schedules, notifications_log, audit_log
"""

import json
from datetime import datetime
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

from config import get

DB_PATH = get("database.path", "data/osint.db")
Path(DB_PATH).parent.mkdir(exist_ok=True)

engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}", echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


# ── MODELS ───────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id           = sa.Column(sa.Integer, primary_key=True)
    username     = sa.Column(sa.String(64), unique=True, nullable=False)
    password_hash= sa.Column(sa.String(256), nullable=False)
    role         = sa.Column(sa.String(16), default="analyst")  # admin / analyst / viewer
    created_at   = sa.Column(sa.DateTime, default=datetime.utcnow)
    last_login   = sa.Column(sa.DateTime, nullable=True)
    failed_attempts = sa.Column(sa.Integer, default=0)
    locked_until = sa.Column(sa.DateTime, nullable=True)
    active       = sa.Column(sa.Boolean, default=True)


class Target(Base):
    __tablename__ = "targets"
    id           = sa.Column(sa.Integer, primary_key=True)
    value        = sa.Column(sa.String(256), nullable=False)
    input_type   = sa.Column(sa.String(32), default="")
    label        = sa.Column(sa.String(128), default="")   # friendly name
    tags         = sa.Column(sa.Text, default="[]")        # JSON list
    notes        = sa.Column(sa.Text, default="")
    owner_id     = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    created_at   = sa.Column(sa.DateTime, default=datetime.utcnow)
    last_scanned = sa.Column(sa.DateTime, nullable=True)


class Scan(Base):
    __tablename__ = "scans"
    id           = sa.Column(sa.String(16), primary_key=True)
    target_value = sa.Column(sa.String(256), nullable=False)
    target_id    = sa.Column(sa.Integer, sa.ForeignKey("targets.id"), nullable=True)
    input_type   = sa.Column(sa.String(32), default="")
    modules      = sa.Column(sa.Text, default="[]")
    status       = sa.Column(sa.String(16), default="pending")  # pending/running/done/failed
    progress     = sa.Column(sa.Integer, default=0)
    step         = sa.Column(sa.String(256), default="Queued")
    results      = sa.Column(sa.Text, nullable=True)
    diff         = sa.Column(sa.Text, nullable=True)   # JSON diff vs previous scan
    risk_level   = sa.Column(sa.String(16), nullable=True)
    risk_score   = sa.Column(sa.Integer, nullable=True)
    owner_id     = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    triggered_by = sa.Column(sa.String(32), default="manual")  # manual / schedule
    created_at   = sa.Column(sa.DateTime, default=datetime.utcnow)
    completed_at = sa.Column(sa.DateTime, nullable=True)
    notified     = sa.Column(sa.Boolean, default=False)


class Schedule(Base):
    __tablename__ = "schedules"
    id           = sa.Column(sa.Integer, primary_key=True)
    target_id    = sa.Column(sa.Integer, sa.ForeignKey("targets.id"), nullable=False)
    modules      = sa.Column(sa.Text, default="[]")
    interval_hours = sa.Column(sa.Integer, default=24)
    enabled      = sa.Column(sa.Boolean, default=True)
    last_run     = sa.Column(sa.DateTime, nullable=True)
    next_run     = sa.Column(sa.DateTime, nullable=True)
    created_by   = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    created_at   = sa.Column(sa.DateTime, default=datetime.utcnow)
    notify_on_change = sa.Column(sa.Boolean, default=True)


class FindingNote(Base):
    __tablename__ = "finding_notes"
    id           = sa.Column(sa.Integer, primary_key=True)
    scan_id      = sa.Column(sa.String(16), sa.ForeignKey("scans.id"), nullable=False)
    finding_key  = sa.Column(sa.String(256), nullable=False)  # e.g. "CVE-2023-1234" or "nuclei:template-id"
    status       = sa.Column(sa.String(32), default="open")  # open / false_positive / accepted_risk / remediated
    note         = sa.Column(sa.Text, default="")
    owner_id     = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    updated_at   = sa.Column(sa.DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id           = sa.Column(sa.Integer, primary_key=True)
    user_id      = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    username     = sa.Column(sa.String(64), default="")
    action       = sa.Column(sa.String(64), nullable=False)
    detail       = sa.Column(sa.Text, default="")
    ip_address   = sa.Column(sa.String(64), default="")
    timestamp    = sa.Column(sa.DateTime, default=datetime.utcnow)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
