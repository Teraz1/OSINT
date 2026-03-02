"""
scheduler.py — Background task that checks for due scheduled scans and runs them.
Lightweight: just an asyncio loop that wakes every N minutes.
No Celery needed for scheduling itself.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta

import sqlalchemy as sa

from config import get
from database import AsyncSessionLocal, Scan, Schedule, Target

logger = logging.getLogger("scheduler")


async def _get_due_schedules(db) -> list:
    now = datetime.utcnow()
    result = await db.execute(
        sa.select(Schedule).where(
            Schedule.enabled == True,
            sa.or_(Schedule.next_run <= now, Schedule.next_run == None)
        )
    )
    return result.scalars().all()


async def _create_scan_for_schedule(db, schedule: Schedule) -> str | None:
    target = await db.get(Target, schedule.target_id)
    if not target:
        return None

    scan_id = str(uuid.uuid4())[:8]
    scan = Scan(
        id=scan_id,
        target_value=target.value,
        target_id=target.id,
        input_type=target.input_type,
        modules=schedule.modules,
        status="pending",
        step="Scheduled",
        triggered_by="schedule",
        owner_id=schedule.created_by,
    )
    db.add(scan)

    # Update schedule next_run
    schedule.last_run = datetime.utcnow()
    schedule.next_run = datetime.utcnow() + timedelta(hours=schedule.interval_hours)
    await db.commit()
    logger.info(f"Scheduled scan {scan_id} created for target: {target.value}")
    return scan_id


async def run_scheduled_scan(scan_id: str):
    """Kick off a scheduled scan — imported from backend at runtime to avoid circular import."""
    from backend import execute_scan
    await execute_scan(scan_id)


async def scheduler_loop():
    """Main scheduler loop. Runs forever, wakes every interval_minutes."""
    if not get("scheduling.enabled", True):
        logger.info("Scheduler disabled in config.")
        return

    interval = get("scheduling.check_interval_minutes", 5) * 60
    logger.info(f"Scheduler started — checking every {interval//60} minutes")

    while True:
        try:
            async with AsyncSessionLocal() as db:
                due = await _get_due_schedules(db)
                for schedule in due:
                    scan_id = await _create_scan_for_schedule(db, schedule)
                    if scan_id:
                        asyncio.ensure_future(run_scheduled_scan(scan_id))
        except Exception as e:
            logger.error(f"Scheduler error: {e}")

        await asyncio.sleep(interval)
