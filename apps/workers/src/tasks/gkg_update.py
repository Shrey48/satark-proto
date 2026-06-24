"""SATARK Layer 1 — GKG update tasks (Section 14.4)"""
from celery_app import celery_app
import structlog

logger = structlog.get_logger(__name__)


@celery_app.task(name="tasks.gkg_update.update_alert_signatures")
def update_alert_signatures():
    """Weekly pull of Snort/Suricata community ruleset and GuardDuty finding types."""
    logger.info("gkg_alert_signature_update_running")
