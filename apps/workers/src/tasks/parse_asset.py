"""SATARK Layer 1 — Parse asset tasks (Phase 1 implementation)"""
from celery_app import celery_app
import structlog

logger = structlog.get_logger(__name__)


@celery_app.task(name="tasks.parse_asset.parse_code_repo", bind=True, max_retries=3)
def parse_code_repo(self, org_id: str, asset_id: str, file_path: str):
    """
    Pass 1: Parse a code repository file into a local graph fragment.
    Implemented in Phase 1 (P1-01).
    """
    logger.info("parse_code_repo_queued", org_id=org_id, asset_id=asset_id)
    # Phase 1 implementation goes here


@celery_app.task(name="tasks.parse_asset.parse_iac", bind=True, max_retries=3)
def parse_iac(self, org_id: str, asset_id: str, file_path: str):
    """Pass 1: Parse a Terraform/CloudFormation file. Implemented in Phase 1 (P1-02)."""
    logger.info("parse_iac_queued", org_id=org_id, asset_id=asset_id)
