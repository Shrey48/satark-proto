"""
SATARK Layer 1 — CI/CD Pipeline Parser (B4)
Handles: GitHub Actions (.github/workflows/*.yml), GitLab CI (.gitlab-ci.yml),
         Jenkins (Jenkinsfile), generic CI YAML.

Produces:
- Pipeline node
- Stage nodes
- Job nodes
- Step nodes
- SecretInjection nodes (where secrets are referenced — attack surface)

Entry points: none (CI/CD pipelines are not external attack surface)
Security-relevant nodes: SecretInjection (where secrets enter the pipeline)
"""
import yaml
import re
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# Secret reference patterns across CI systems
SECRET_PATTERNS = [
    r'\$\{\{\s*secrets\.',          # GitHub Actions: ${{ secrets.NAME }}
    r'\$\{\{\s*env\.',              # GitHub Actions: ${{ env.NAME }}
    r'\$SECRET_',                   # GitLab/generic: $SECRET_NAME
    r'secretKeyRef',                # K8s-style secret reference
    r'\$\(params\.',                # Tekton pipeline params
]


def _has_secret_ref(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return any(re.search(p, value) for p in SECRET_PATTERNS)


def _extract_secrets_from_env(env: dict) -> list[str]:
    """Extract secret names from an env block."""
    secrets = []
    if not isinstance(env, dict):
        return secrets
    for k, v in env.items():
        if _has_secret_ref(str(v)):
            secrets.append(k)
    return secrets


def _make_entity_id(*parts: str) -> str:
    safe = ".".join(
        re.sub(r'[^a-z0-9_]', '_', str(p).lower())
        for p in parts
    )
    return f"{ORG_ID}::cicd::pipeline::{safe}"


def _detect_format(content: str, file_path: str) -> str:
    """Detect CI/CD format from file path and content."""
    fp = file_path.lower()
    if ".github/workflows" in fp:
        return "github_actions"
    if ".gitlab-ci" in fp:
        return "gitlab_ci"
    if "jenkinsfile" in fp:
        return "jenkins"
    if "circleci" in fp or ".circleci" in fp:
        return "circle_ci"
    # Heuristic from content
    if "on:" in content and "jobs:" in content:
        return "github_actions"
    if "stages:" in content and "script:" in content:
        return "gitlab_ci"
    return "generic_ci"


def parse_cicd_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="cicd")

    fmt = _detect_format(content, file_path)

    try:
        spec = yaml.safe_load(content)
    except yaml.YAMLError as e:
        logger.error("cicd_yaml_parse_error", file=file_path, error=str(e))
        return fragment

    if not spec or not isinstance(spec, dict):
        return fragment

    if fmt == "github_actions":
        return _parse_github_actions(spec, content, file_path, asset_id, fragment)
    elif fmt == "gitlab_ci":
        return _parse_gitlab_ci(spec, content, file_path, asset_id, fragment)
    else:
        return _parse_generic_ci(spec, content, file_path, asset_id, fragment)


def _parse_github_actions(spec: dict, content: str, file_path: str,
                           asset_id: str, fragment: GraphFragment) -> GraphFragment:
    """Parse GitHub Actions workflow YAML."""
    pipeline_name = spec.get("name") or file_path.split("/")[-1].replace(".yml", "")
    pipeline_id   = _make_entity_id(pipeline_name, "pipeline")

    # Triggers
    on_triggers = spec.get("on", {})
    trigger_list = []
    if isinstance(on_triggers, dict):
        trigger_list = list(on_triggers.keys())
    elif isinstance(on_triggers, list):
        trigger_list = on_triggers
    elif isinstance(on_triggers, str):
        trigger_list = [on_triggers]

    fragment.nodes.append(KGNode(
        entity_id=pipeline_id, node_type="Pipeline", domain_type="cicd",
        name=pipeline_name,
        source_location=SourceLocation(file_path=file_path, block_identifier="workflow"),
        metadata=NodeMetadata(
            semantic_summary=f"GitHub Actions workflow '{pipeline_name}' "
                             f"triggered by: {', '.join(trigger_list[:3])}",
            resolved_by="deterministic",
        ),
        properties={"format": "github_actions", "triggers": trigger_list},
        org_id=ORG_ID,
    ))

    jobs = spec.get("jobs", {}) or {}
    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue

        job_id  = _make_entity_id(pipeline_name, "job", job_name)
        runs_on = job_def.get("runs-on", "unknown")
        env     = job_def.get("env", {})
        job_secrets = _extract_secrets_from_env(env)

        fragment.nodes.append(KGNode(
            entity_id=job_id, node_type="Job", domain_type="cicd",
            name=job_name,
            source_location=SourceLocation(
                file_path=file_path, block_identifier=f"jobs.{job_name}"),
            metadata=NodeMetadata(
                semantic_summary=f"Job '{job_name}' runs on {runs_on}",
                resolved_by="deterministic",
            ),
            properties={"runs_on": runs_on, "env_secrets": job_secrets},
            org_id=ORG_ID,
        ))
        fragment.edges.append(KGEdge(
            from_entity_id=pipeline_id, to_entity_id=job_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

        # Steps
        steps = job_def.get("steps", []) or []
        for s_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            step_name = step.get("name") or step.get("uses") or f"step-{s_idx+1}"
            step_id   = _make_entity_id(pipeline_name, "job", job_name, "step", str(s_idx))
            step_env  = step.get("env", {})
            step_with = step.get("with", {})
            step_run  = step.get("run", "")

            step_secrets = _extract_secrets_from_env(step_env)
            step_secrets += _extract_secrets_from_env(step_with)
            if _has_secret_ref(step_run):
                step_secrets.append("inline_secret_in_run")

            fragment.nodes.append(KGNode(
                entity_id=step_id, node_type="Step", domain_type="cicd",
                name=step_name,
                source_location=SourceLocation(
                    file_path=file_path,
                    block_identifier=f"jobs.{job_name}.steps[{s_idx}]"),
                metadata=NodeMetadata(
                    semantic_summary=f"Step '{step_name}'" +
                                     (" — injects secrets" if step_secrets else ""),
                    resolved_by="deterministic",
                ),
                properties={
                    "uses": step.get("uses"),
                    "run": (step_run[:200] if step_run else None),
                    "secrets_injected": step_secrets,
                },
                org_id=ORG_ID,
            ))
            fragment.edges.append(KGEdge(
                from_entity_id=job_id, to_entity_id=step_id,
                edge_type="E_contain", source_asset_ids=[asset_id],
            ))

            # SecretInjection nodes for each secret referenced in this step
            for secret_name in set(step_secrets):
                si_id = _make_entity_id(pipeline_name, "secret", job_name, secret_name)
                if not any(n.entity_id == si_id for n in fragment.nodes):
                    fragment.nodes.append(KGNode(
                        entity_id=si_id, node_type="SecretInjection", domain_type="cicd",
                        name=secret_name,
                        source_location=SourceLocation(
                            file_path=file_path,
                            block_identifier=f"jobs.{job_name}.steps[{s_idx}].env.{secret_name}"),
                        metadata=NodeMetadata(
                            semantic_summary=f"Secret '{secret_name}' injected in step '{step_name}'",
                            resolved_by="deterministic",
                        ),
                        properties={"secret_name": secret_name, "job": job_name},
                        org_id=ORG_ID,
                    ))
                fragment.edges.append(KGEdge(
                    from_entity_id=step_id, to_entity_id=si_id,
                    edge_type="E_contain", source_asset_ids=[asset_id],
                ))

    logger.info("cicd_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges), format="github_actions")
    return fragment


def _parse_gitlab_ci(spec: dict, content: str, file_path: str,
                     asset_id: str, fragment: GraphFragment) -> GraphFragment:
    """Parse GitLab CI YAML."""
    pipeline_name = file_path.split("/")[-1].replace(".yml", "").replace(".yaml", "")
    pipeline_id   = _make_entity_id(pipeline_name, "pipeline")

    stages_list = spec.get("stages", [])

    fragment.nodes.append(KGNode(
        entity_id=pipeline_id, node_type="Pipeline", domain_type="cicd",
        name=pipeline_name,
        source_location=SourceLocation(file_path=file_path, block_identifier="pipeline"),
        metadata=NodeMetadata(
            semantic_summary=f"GitLab CI pipeline with stages: {', '.join(stages_list[:4])}",
            resolved_by="deterministic",
        ),
        properties={"format": "gitlab_ci", "stages": stages_list},
        org_id=ORG_ID,
    ))

    # Each top-level key that isn't a reserved keyword is a job
    RESERVED = {"stages", "variables", "include", "default", "workflow",
                "cache", "before_script", "after_script", "image", "services"}
    for job_name, job_def in spec.items():
        if job_name in RESERVED or not isinstance(job_def, dict):
            continue

        job_id    = _make_entity_id(pipeline_name, "job", job_name)
        stage     = job_def.get("stage", "default")
        variables = job_def.get("variables", {})
        secrets   = _extract_secrets_from_env(variables)

        fragment.nodes.append(KGNode(
            entity_id=job_id, node_type="Job", domain_type="cicd",
            name=job_name,
            source_location=SourceLocation(
                file_path=file_path, block_identifier=f"job.{job_name}"),
            metadata=NodeMetadata(
                semantic_summary=f"GitLab job '{job_name}' in stage '{stage}'",
                resolved_by="deterministic",
            ),
            properties={"stage": stage, "secrets": secrets},
            org_id=ORG_ID,
        ))
        fragment.edges.append(KGEdge(
            from_entity_id=pipeline_id, to_entity_id=job_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

    logger.info("cicd_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges), format="gitlab_ci")
    return fragment


def _parse_generic_ci(spec: dict, content: str, file_path: str,
                      asset_id: str, fragment: GraphFragment) -> GraphFragment:
    """Fallback parser for unknown CI formats — extracts what it can."""
    pipeline_name = file_path.split("/")[-1].replace(".yml", "").replace(".yaml", "")
    pipeline_id   = _make_entity_id(pipeline_name, "pipeline")

    fragment.nodes.append(KGNode(
        entity_id=pipeline_id, node_type="Pipeline", domain_type="cicd",
        name=pipeline_name,
        source_location=SourceLocation(file_path=file_path, block_identifier="pipeline"),
        metadata=NodeMetadata(
            semantic_summary=f"CI/CD pipeline '{pipeline_name}'",
            resolved_by="deterministic",
        ),
        properties={"format": "generic_ci"},
        org_id=ORG_ID,
    ))

    logger.info("cicd_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges), format="generic_ci")
    return fragment
