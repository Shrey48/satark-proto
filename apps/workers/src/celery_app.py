"""
SATARK Layer 1 — Celery Worker Application (P0-16)

Celery handles all async processing:
  - Pass 1/2/3 parsing (submitted per asset, run in background)
  - Track 2 normalisation (per finding, concurrent workers)
  - Scheduled maintenance (staleness sweep, orphan reconciliation, edge decay)

Concurrency note (Section 9.5):
  Multiple normalisation workers run in parallel. Dedup uses optimistic
  locking on (canonical_id, normalised_asset_location) in Neo4j.
"""
from celery import Celery
from celery.schedules import crontab
import os

# Redis as both broker and result backend
REDIS_URI = os.getenv("REDIS_URI", "redis://localhost:6379/0")

celery_app = Celery(
    "satark",
    broker=REDIS_URI,
    backend=REDIS_URI,
    include=[
        "tasks.parse_asset",
        "tasks.link_assets",
        "tasks.normalise_finding",
        "tasks.staleness_sweep",
        "tasks.orphan_reconciliation",
        "tasks.gkg_update",
        "tasks.decay_edges",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,           # Ack after completion, not on receipt (no lost tasks on crash)
    worker_prefetch_multiplier=1,  # One task at a time per worker (parsing tasks are heavy)
    task_routes={
        # Parsing tasks: dedicated queue, fewer workers, high memory
        "tasks.parse_asset.*": {"queue": "parse"},
        "tasks.link_assets.*": {"queue": "link"},
        # Normalisation tasks: high concurrency queue
        "tasks.normalise_finding.*": {"queue": "normalise"},
        # Maintenance tasks: low-priority queue
        "tasks.staleness_sweep.*": {"queue": "maintenance"},
        "tasks.orphan_reconciliation.*": {"queue": "maintenance"},
        "tasks.gkg_update.*": {"queue": "maintenance"},
        "tasks.decay_edges.*": {"queue": "maintenance"},
    },
    beat_schedule={
        # Type A staleness sweep — daily at 02:00 UTC (Section 7.1)
        "type-a-staleness-sweep": {
            "task": "tasks.staleness_sweep.run_staleness_sweep",
            "schedule": crontab(hour=2, minute=0),
        },
        # Orphan finding reconciliation — every 30 minutes (Section 7.5)
        "orphan-reconciliation": {
            "task": "tasks.orphan_reconciliation.run_reconciliation",
            "schedule": crontab(minute="*/30"),
        },
        # B2 network edge decay check — every 6 hours (Section 2.2)
        "network-edge-decay": {
            "task": "tasks.decay_edges.run_decay_check",
            "schedule": crontab(minute=0, hour="*/6"),
        },
        # GKG alert signature update — weekly Sundays at 03:00 UTC (Section 14.4)
        "gkg-alert-signature-update": {
            "task": "tasks.gkg_update.update_alert_signatures",
            "schedule": crontab(hour=3, minute=0, day_of_week="sunday"),
        },
    },
)
