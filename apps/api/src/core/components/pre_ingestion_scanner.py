"""
SATARK Layer 1 — Component 8 Pre-Ingestion Scanner (spec Section 4.2)

Runs BEFORE Pass 1 begins. Scans every ground truth file and extracts
self-declared names from known, fixed locations in each file format.
Builds the alias table so that by the time parsers run, the system already
knows that checkout-service, checkout_svc, and checkout are the same entity.

Per spec: reads from fixed, known fields only — never infers names from content.
Supported fields per format:
  Terraform:    tags.Name, tags.service, tags.app, resource block label
  K8s:          metadata.name, metadata.labels.app, app.kubernetes.io/name
  Python:       (none — names extracted from AST in Pass 1)
  OpenAPI:      info.title, info.x-service-name
  IAM:          PolicyName
  GitHub Actions: workflow name field
  Dockerfile:   LABEL service=, LABEL app=, LABEL name=
"""
import re
import yaml
import json
from typing import Optional
from core.components.registry import write_alias
import structlog

logger = structlog.get_logger(__name__)


async def scan_and_seed_aliases(
    content: str,
    file_path: str,
    asset_id: str,
    org_id: str = "prototype",
) -> list[str]:
    """
    Scan a single file and extract self-declared names.
    Writes each name → asset_id alias to Component 8.
    Returns list of names extracted.
    """
    fp = file_path.lower()
    names = []

    try:
        if fp.endswith(".tf"):
            names = _scan_terraform(content, file_path)
        elif fp.endswith((".yaml", ".yml")):
            names = _scan_yaml(content, file_path)
        elif fp.endswith(".json"):
            names = _scan_json(content, file_path)
        elif "dockerfile" in fp:
            names = _scan_dockerfile(content, file_path)
        elif fp.endswith(".py"):
            names = _scan_python(content, file_path)
    except Exception as e:
        logger.warning("pre_ingestion_scan_error", file=file_path, error=str(e))
        return []

    # Write each extracted name as an alias for this asset_id
    for name in names:
        if name and len(name) > 2:
            await write_alias(
                org_id=org_id,
                informal_name=name.lower().replace("-", "_"),
                canonical_entity_id=asset_id,
                context=_get_file_domain(file_path),
            )
            # Also write with hyphen variant
            if "_" in name:
                await write_alias(
                    org_id=org_id,
                    informal_name=name.lower().replace("_", "-"),
                    canonical_entity_id=asset_id,
                    context=_get_file_domain(file_path),
                )

    if names:
        logger.info("pre_ingestion_aliases_seeded",
                    file=file_path, names=names, asset_id=asset_id)

    return names


def _get_file_domain(file_path: str) -> str:
    fp = file_path.lower()
    if fp.endswith(".tf"):           return "cloud"
    if "dockerfile" in fp:           return "container"
    if fp.endswith(".py"):           return "code"
    return "unknown"


def _scan_terraform(content: str, file_path: str) -> list[str]:
    names = set()

    # Extract tags.Name, tags.service, tags.app
    for m in re.finditer(r'tags\s*=\s*\{([^}]+)\}', content, re.DOTALL):
        tag_block = m.group(1)
        for key in ("Name", "service", "app", "name"):
            tm = re.search(rf'{key}\s*=\s*"([^"]+)"', tag_block)
            if tm:
                names.add(tm.group(1))

    # Resource block labels: resource "type" "label" {}
    for m in re.finditer(r'^resource\s+"[^"]+"\s+"([^"]+)"', content, re.MULTILINE):
        names.add(m.group(1).replace("_", "-"))

    return [n for n in names if n]


def _scan_yaml(content: str, file_path: str) -> list[str]:
    names = set()
    fp    = file_path.lower()

    try:
        docs = list(yaml.safe_load_all(content))
    except Exception:
        return []

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        # GitHub Actions workflow name
        if "on" in doc and "jobs" in doc:
            if "name" in doc:
                names.add(doc["name"])

        # K8s metadata.name, metadata.labels
        meta = doc.get("metadata", {}) or {}
        if "name" in meta:
            names.add(meta["name"])
        labels = meta.get("labels", {}) or {}
        for key in ("app", "app.kubernetes.io/name", "app.kubernetes.io/instance"):
            if key in labels:
                names.add(labels[key])

        # OpenAPI info.title
        info = doc.get("info", {}) or {}
        if "title" in info:
            names.add(info["title"].lower().replace(" ", "-"))
        if "x-service-name" in info:
            names.add(info["x-service-name"])

    return [n for n in names if n]


def _scan_json(content: str, file_path: str) -> list[str]:
    names = set()
    try:
        data = json.loads(content)
    except Exception:
        return []

    # Unwrap single-key wrapper (LLM-generated format)
    if isinstance(data, dict) and len(data) == 1:
        inner = list(data.values())[0]
        if isinstance(inner, dict):
            data = inner

    if not isinstance(data, dict):
        return []

    # IAM: PolicyName
    for key in ("PolicyName", "name", "policy_name"):
        if key in data:
            names.add(str(data[key]))
    # Nested: metadata.PolicyName
    meta = data.get("metadata", {}) or {}
    for key in ("PolicyName", "name"):
        if key in meta:
            names.add(str(meta[key]))

    return [n for n in names if n]


def _scan_dockerfile(content: str, file_path: str) -> list[str]:
    names = set()
    for m in re.finditer(r'^LABEL\s+(service|app|name)=(["\']?)(\S+)\2', content, re.MULTILINE | re.IGNORECASE):
        names.add(m.group(3).strip('"\''))
    return [n for n in names if n]


def _scan_python(content: str, file_path: str) -> list[str]:
    """Python modules — extract Flask app name and class names as service hints."""
    names = set()
    # package name from __version__ or app = Flask(__name__)
    m = re.search(r"app\s*=\s*Flask\s*\(\s*__name__\s*\)", content)
    if m:
        # Use the file name as the service hint
        service = file_path.split("/")[-1].replace(".py", "").replace("_", "-")
        names.add(service)
    return [n for n in names if n]
