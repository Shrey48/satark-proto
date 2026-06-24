"""SATARK Layer 1 — Type A staleness sweep (Section 7.1)"""
from celery_app import celery_app
import structlog

logger = structlog.get_logger(__name__)


@celery_app.task(name="tasks.staleness_sweep.run_staleness_sweep")
def run_staleness_sweep():
    """
    Daily scheduled task. Queries all Type A findings where
    (now - report_generated_at) > staleness_window and sets temporal_status: stale.
    Implemented in Phase 4 (P4-06).
    """
    logger.info("staleness_sweep_running")
