"""
SATARK Layer 1 — entity_id Scheme (Section 3.6)

Format: <tenant_id>::<domain_type>::<asset_id>::<local_id>

All temporal versions of the same real-world entity share the same entity_id.
The bitemporal model (valid_from, valid_to) on each version distinguishes them.
Current-state queries: WHERE valid_to IS NULL
"""
import re
from dataclasses import dataclass


SEPARATOR = "::"
ALLOWED_CHARS = re.compile(r'^[a-z0-9\-_./]+$')


@dataclass(frozen=True)
class EntityId:
    tenant_id: str       # Organisation's SATARK tenant identifier
    domain_type: str     # One of the 12 domain_type values
    asset_id: str        # Stable identifier for the source asset
    local_id: str        # Resource's own stable identifier within the asset

    def __post_init__(self):
        for field_name, value in [
            ("tenant_id", self.tenant_id),
            ("domain_type", self.domain_type),
            ("asset_id", self.asset_id),
            ("local_id", self.local_id),
        ]:
            if not value:
                raise ValueError(f"entity_id.{field_name} cannot be empty")
            if SEPARATOR in value:
                raise ValueError(f"entity_id.{field_name} cannot contain '{SEPARATOR}'")

    def __str__(self) -> str:
        return f"{self.tenant_id}{SEPARATOR}{self.domain_type}{SEPARATOR}{self.asset_id}{SEPARATOR}{self.local_id}"

    @classmethod
    def from_string(cls, entity_id_str: str) -> "EntityId":
        parts = entity_id_str.split(SEPARATOR)
        if len(parts) != 4:
            raise ValueError(f"Invalid entity_id format: '{entity_id_str}'. Expected 4 segments separated by '::'")
        return cls(*parts)

    def neo4j_db_name(self) -> str:
        """Returns the Neo4j database name for this tenant."""
        return f"vargplus_tenant_{self.tenant_id.replace('-', '_')}"


# Domain types from spec Section 3.2
VALID_DOMAIN_TYPES = {
    "code", "api", "cloud", "iam", "cicd", "k8s",
    "data_pipeline", "container", "mobile", "ai_llm", "grc", "threat_intel"
}


def build_entity_id(tenant_id: str, domain_type: str, asset_id: str, local_id: str) -> str:
    """Build and validate an entity_id string."""
    if domain_type not in VALID_DOMAIN_TYPES:
        raise ValueError(f"Invalid domain_type '{domain_type}'. Must be one of: {VALID_DOMAIN_TYPES}")
    eid = EntityId(
        tenant_id=tenant_id.lower(),
        domain_type=domain_type,
        asset_id=asset_id.lower(),
        local_id=local_id.lower(),
    )
    return str(eid)
