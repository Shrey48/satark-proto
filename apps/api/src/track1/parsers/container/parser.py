"""
SATARK Layer 1 — Container/Dockerfile Parser (A7/G1)
Handles: Dockerfile, docker-compose.yml, .dockerignore

Produces per spec Section 2.1:
  ContainerImage node — the image being built
  BaseImage node     — FROM instruction target
  Layer nodes        — each RUN/COPY/ADD instruction
  EnvVar nodes       — ENV declarations (credential exposure risk)

Entry points: none (containers are not external attack surfaces by themselves)
Security-relevant nodes: EnvVar nodes with credential patterns, EXPOSE of sensitive ports
"""
import re
import yaml
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# Sensitive ports per GKG SensitivePort registry
SENSITIVE_PORTS = {22, 3389, 5432, 3306, 27017, 6379, 9200, 1433, 2379, 10250}

# Patterns that suggest credential exposure in ENV
CREDENTIAL_PATTERNS = [
    r'PASSWORD', r'SECRET', r'API_KEY', r'TOKEN', r'PRIVATE_KEY',
    r'AWS_SECRET', r'DATABASE_URL', r'AUTH_KEY', r'CREDENTIALS',
]


def _has_credential_pattern(name: str) -> bool:
    return any(re.search(p, name.upper()) for p in CREDENTIAL_PATTERNS)


def _make_entity_id(*parts: str) -> str:
    safe = ".".join(re.sub(r'[^a-z0-9_.-]', '_', str(p).lower()) for p in parts)
    return f"{ORG_ID}::container::image::{safe}"


def _detect_format(content: str, file_path: str) -> str:
    fp = file_path.lower()
    if 'dockerfile' in fp:
        return 'dockerfile'
    if 'docker-compose' in fp or 'compose' in fp:
        return 'compose'
    # Heuristic
    if content.strip().upper().startswith('FROM '):
        return 'dockerfile'
    return 'compose'


def parse_container_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="container")

    fmt = _detect_format(content, file_path)
    if fmt == 'dockerfile':
        return _parse_dockerfile(content, file_path, asset_id, fragment)
    else:
        return _parse_compose(content, file_path, asset_id, fragment)


def _parse_dockerfile(content: str, file_path: str, asset_id: str,
                      fragment: GraphFragment) -> GraphFragment:
    """Parse a Dockerfile into graph fragment."""
    lines = content.split('\n')
    image_name = asset_id.replace('container-', '')

    image_id = _make_entity_id(image_name, "image")
    fragment.nodes.append(KGNode(
        entity_id=image_id, node_type="ContainerImage", domain_type="container",
        name=image_name,
        source_location=SourceLocation(file_path=file_path, start_line=1, end_line=len(lines)),
        metadata=NodeMetadata(
            semantic_summary=f"Container image built from {file_path}",
            resolved_by="deterministic",
        ),
        properties={"format": "dockerfile"},
        org_id=ORG_ID,
    ))

    layer_index   = 0
    exposed_ports = []
    base_image    = None

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip comments and empty lines
        if not line or line.startswith('#'):
            i += 1; continue

        # Handle line continuation
        while line.endswith('\\') and i + 1 < len(lines):
            i += 1
            line = line[:-1] + ' ' + lines[i].strip()

        parts = line.split(None, 1)
        if not parts:
            i += 1; continue
        instruction = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        # FROM — base image
        if instruction == "FROM":
            # FROM image[:tag] [AS name]
            from_parts = arg.split()
            base_ref   = from_parts[0]
            stage_name = from_parts[2] if len(from_parts) >= 3 and from_parts[1].upper() == "AS" else None

            base_id = _make_entity_id(image_name, "base", base_ref.replace('/', '_').replace(':', '_'))
            if not any(n.entity_id == base_id for n in fragment.nodes):
                fragment.nodes.append(KGNode(
                    entity_id=base_id, node_type="BaseImage", domain_type="container",
                    name=base_ref,
                    source_location=SourceLocation(file_path=file_path, start_line=i+1, end_line=i+1),
                    metadata=NodeMetadata(
                        semantic_summary=f"Base image: {base_ref}" + (f" (stage: {stage_name})" if stage_name else ""),
                        resolved_by="deterministic",
                    ),
                    properties={"base_ref": base_ref, "stage_name": stage_name},
                    org_id=ORG_ID,
                ))
            fragment.edges.append(KGEdge(
                from_entity_id=image_id, to_entity_id=base_id,
                edge_type="E_contain", source_asset_ids=[asset_id],
            ))
            base_image = base_ref

        # RUN, COPY, ADD — layers
        elif instruction in ("RUN", "COPY", "ADD"):
            layer_id = _make_entity_id(image_name, "layer", str(layer_index))
            layer_index += 1

            summary = f"{instruction}: {arg[:80]}"
            # Flag potentially dangerous patterns
            flags = []
            if instruction == "RUN":
                if re.search(r'curl\s+.*\|\s*(bash|sh)', arg):
                    flags.append("curl_pipe_bash")
                if re.search(r'wget\s+.*\|\s*(bash|sh)', arg):
                    flags.append("wget_pipe_bash")
                if '--no-check-certificate' in arg or '--insecure' in arg:
                    flags.append("tls_verification_disabled")
            if instruction in ("COPY", "ADD") and re.search(r'\.\s+\.', arg):
                flags.append("copies_entire_context")

            fragment.nodes.append(KGNode(
                entity_id=layer_id, node_type="Layer", domain_type="container",
                name=f"{instruction}[{layer_index}]",
                source_location=SourceLocation(file_path=file_path, start_line=i+1, end_line=i+1),
                metadata=NodeMetadata(
                    semantic_summary=summary,
                    resolved_by="deterministic",
                ),
                properties={"instruction": instruction, "arg": arg[:500],
                            "flags": flags, "layer_index": layer_index},
                org_id=ORG_ID,
            ))
            fragment.edges.append(KGEdge(
                from_entity_id=image_id, to_entity_id=layer_id,
                edge_type="E_contain", source_asset_ids=[asset_id],
            ))

        # ENV — environment variables
        elif instruction == "ENV":
            # ENV KEY=VALUE or ENV KEY VALUE (legacy)
            env_pairs = {}
            if '=' in arg:
                for pair in re.findall(r'(\w+)=("[^"]*"|\'[^\']*\'|\S*)', arg):
                    env_pairs[pair[0]] = pair[1].strip('"\'')
            else:
                parts2 = arg.split(None, 1)
                if len(parts2) == 2:
                    env_pairs[parts2[0]] = parts2[1]

            for env_name, env_val in env_pairs.items():
                env_id = _make_entity_id(image_name, "env", env_name)
                is_credential = _has_credential_pattern(env_name)
                fragment.nodes.append(KGNode(
                    entity_id=env_id, node_type="EnvVar", domain_type="container",
                    name=env_name,
                    source_location=SourceLocation(file_path=file_path, start_line=i+1, end_line=i+1),
                    metadata=NodeMetadata(
                        semantic_summary=f"ENV {env_name}" +
                                         (" — ⚠ credential pattern detected" if is_credential else ""),
                        resolved_by="deterministic",
                    ),
                    properties={
                        "env_name": env_name,
                        # Never store actual env values — only structural metadata
                        "has_value": bool(env_val),
                        "credential_pattern": is_credential,
                    },
                    org_id=ORG_ID,
                ))
                fragment.edges.append(KGEdge(
                    from_entity_id=image_id, to_entity_id=env_id,
                    edge_type="E_contain", source_asset_ids=[asset_id],
                ))

        # EXPOSE — port declarations
        elif instruction == "EXPOSE":
            for port_str in arg.split():
                port_num = int(port_str.split('/')[0]) if port_str.split('/')[0].isdigit() else None
                if port_num:
                    exposed_ports.append(port_num)

        i += 1

    # Update image node with exposed ports
    if exposed_ports:
        for node in fragment.nodes:
            if node.entity_id == image_id:
                node.properties["exposed_ports"] = exposed_ports
                sensitive = [p for p in exposed_ports if p in SENSITIVE_PORTS]
                if sensitive:
                    node.metadata.semantic_summary += f" — exposes sensitive ports: {sensitive}"

    logger.info("container_dockerfile_parsed", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges),
                base=base_image, layers=layer_index)
    return fragment


def _parse_compose(content: str, file_path: str, asset_id: str,
                   fragment: GraphFragment) -> GraphFragment:
    """Parse docker-compose.yml into graph fragment."""
    try:
        spec = yaml.safe_load(content)
    except yaml.YAMLError as e:
        logger.error("container_compose_parse_error", file=file_path, error=str(e))
        return fragment

    if not spec or not isinstance(spec, dict):
        return fragment

    compose_id = _make_entity_id(asset_id, "compose")
    fragment.nodes.append(KGNode(
        entity_id=compose_id, node_type="ContainerImage", domain_type="container",
        name=file_path.split("/")[-1].replace(".yml", "").replace(".yaml", ""),
        source_location=SourceLocation(file_path=file_path, block_identifier="compose"),
        metadata=NodeMetadata(
            semantic_summary=f"Docker Compose file: {file_path}",
            resolved_by="deterministic",
        ),
        properties={"format": "docker_compose"},
        org_id=ORG_ID,
    ))

    services = spec.get("services", {}) or {}
    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        svc_id  = _make_entity_id(asset_id, "service", svc_name)
        image   = svc_def.get("image", "")
        build   = svc_def.get("build", "")
        ports   = svc_def.get("ports", [])
        env     = svc_def.get("environment", {}) or {}

        exposed = []
        for p in (ports or []):
            p_str = str(p).split(":")[-1].split("/")[0]
            if p_str.isdigit():
                exposed.append(int(p_str))

        fragment.nodes.append(KGNode(
            entity_id=svc_id, node_type="ContainerImage", domain_type="container",
            name=svc_name,
            source_location=SourceLocation(file_path=file_path, block_identifier=f"services.{svc_name}"),
            metadata=NodeMetadata(
                semantic_summary=f"Compose service '{svc_name}'"
                                 + (f" image: {image}" if image else " (built locally)"),
                resolved_by="deterministic",
            ),
            properties={"image": image, "build": str(build), "exposed_ports": exposed},
            org_id=ORG_ID,
        ))
        fragment.edges.append(KGEdge(
            from_entity_id=compose_id, to_entity_id=svc_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

        # Env vars with credential detection
        env_dict = env if isinstance(env, dict) else {}
        for env_name in env_dict:
            if _has_credential_pattern(str(env_name)):
                env_id = _make_entity_id(asset_id, "service", svc_name, "env", str(env_name))
                fragment.nodes.append(KGNode(
                    entity_id=env_id, node_type="EnvVar", domain_type="container",
                    name=str(env_name),
                    source_location=SourceLocation(
                        file_path=file_path,
                        block_identifier=f"services.{svc_name}.environment.{env_name}"),
                    metadata=NodeMetadata(
                        semantic_summary=f"ENV {env_name} — ⚠ credential pattern",
                        resolved_by="deterministic",
                    ),
                    properties={"env_name": str(env_name), "credential_pattern": True,
                                "service": svc_name},
                    org_id=ORG_ID,
                ))
                fragment.edges.append(KGEdge(
                    from_entity_id=svc_id, to_entity_id=env_id,
                    edge_type="E_contain", source_asset_ids=[asset_id],
                ))

    logger.info("container_compose_parsed", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges),
                services=len(services))
    return fragment
