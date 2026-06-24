"""SATARK Layer 1 — Normalisation tasks (Phase 5 implementation)"""
from celery_app import celery_app
import structlog

logger = structlog.get_logger(__name__)


@celery_app.task(name="tasks.normalise_finding.normalise", bind=True, max_retries=5)
def normalise(self, org_id: str, raw_finding: dict):
    """
    6-step normalisation funnel for a single finding.
    Implemented in Phase 5 (P5-01 through P5-15).
    """
    logger.info("normalise_queued", org_id=org_id, tool=raw_finding.get("tool_name"))
