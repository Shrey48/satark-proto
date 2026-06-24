"""SATARK Layer 1 — Ingestion Routes"""
import os, uuid
from fastapi import APIRouter, UploadFile, File, HTTPException
from track1.parsers.iac.parser import parse_terraform_file
from track1.parsers.k8s.parser import parse_k8s_file
from track1.parsers.code.parser import parse_python_file
from track1.parsers.openapi.parser import parse_openapi_file
from track1.parsers.iam.parser import parse_iam_file
from track1.parsers.cicd.parser import parse_cicd_file
from track1.parsers.container.parser import parse_container_file
from track1.parsers.compliance.parser import parse_compliance_file
from core.components.pre_ingestion_scanner import scan_and_seed_aliases
from track1.neo4j_writer import write_fragment
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)
os.makedirs("/app/uploads", exist_ok=True)


def _resp(asset_id, filename, fragment, result):
    return {"status": "ok", "asset_id": asset_id, "file": filename,
            "nodes_created": result["nodes"], "edges_created": result["edges"],
            "entry_points": fragment.entry_points,
            "message": f"Parsed {len(fragment.nodes)} nodes from {filename}"}


@router.post("/terraform")
async def ingest_terraform(file: UploadFile = File(...)):
    if not file.filename.endswith(".tf"): raise HTTPException(400, "Only .tf files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"terraform-{file.filename.replace('.tf','')}-{str(uuid.uuid4())[:8]}"
    await scan_and_seed_aliases(content, file.filename, asset_id)
    fragment = parse_terraform_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/k8s")
async def ingest_k8s(file: UploadFile = File(...)):
    if not (file.filename.endswith(".yaml") or file.filename.endswith(".yml")):
        raise HTTPException(400, "Only .yaml/.yml files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"k8s-{file.filename.replace('.yaml','').replace('.yml','')}-{str(uuid.uuid4())[:8]}"
    await scan_and_seed_aliases(content, file.filename, asset_id)
    fragment = parse_k8s_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/code/python")
async def ingest_python(file: UploadFile = File(...)):
    if not file.filename.endswith(".py"): raise HTTPException(400, "Only .py files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"code-{file.filename.replace('.py','')}-{str(uuid.uuid4())[:8]}"
    fragment = parse_python_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/openapi")
async def ingest_openapi(file: UploadFile = File(...)):
    if not any(file.filename.endswith(e) for e in (".yaml", ".yml", ".json")):
        raise HTTPException(400, "Only .yaml/.yml/.json files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"api-{file.filename.split('.')[0]}-{str(uuid.uuid4())[:8]}"
    fragment = parse_openapi_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/iam")
async def ingest_iam(file: UploadFile = File(...)):
    if not file.filename.endswith(".json"): raise HTTPException(400, "Only .json files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"iam-{file.filename.replace('.json','')}-{str(uuid.uuid4())[:8]}"
    await scan_and_seed_aliases(content, file.filename, asset_id)
    fragment = parse_iam_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/cicd")
async def ingest_cicd(file: UploadFile = File(...)):
    if not any(file.filename.endswith(e) for e in (".yml", ".yaml")):
        raise HTTPException(400, "Only .yml/.yaml files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"cicd-{file.filename.split('.')[0]}-{str(uuid.uuid4())[:8]}"
    fragment = parse_cicd_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/container")
async def ingest_container(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8")
    asset_id = f"container-{file.filename.split('.')[0]}-{str(uuid.uuid4())[:8]}"
    fragment = parse_container_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))


@router.post("/compliance")
async def ingest_compliance(file: UploadFile = File(...)):
    if not any(file.filename.endswith(e) for e in (".json", ".yaml", ".yml")):
        raise HTTPException(400, "Only .json/.yaml/.yml files")
    content = (await file.read()).decode("utf-8")
    asset_id = f"compliance-{file.filename.split('.')[0]}-{str(uuid.uuid4())[:8]}"
    fragment = parse_compliance_file(content=content, file_path=file.filename, asset_id=asset_id)
    return _resp(asset_id, file.filename, fragment, await write_fragment(fragment))
