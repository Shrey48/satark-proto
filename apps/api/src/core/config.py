"""
SATARK Layer 1 — Core Configuration
Every env var the system needs, typed and validated via Pydantic Settings.
Every service reads from this. Nothing reads directly from os.environ.
"""
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # ── Application ────────────────────────────────────────────
    app_env: str = "development"
    app_secret_key: str = "change-me-in-production"
    api_port: int = 8000

    # ── Neo4j ──────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "satark-dev-password"
    neo4j_shared_db: str = "vargplus_shared_reference"

    # ── PostgreSQL ─────────────────────────────────────────────
    postgres_uri: str = "postgresql://satark:satark-dev@localhost:5432/satark"

    # ── Redis ──────────────────────────────────────────────────
    redis_uri: str = "redis://localhost:6379/0"

    # ── Kafka ──────────────────────────────────────────────────
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_type_c: str = "satark.findings.type_c"

    # ── LLM Provider (Section 4.1 — exactly three touchpoints)
    # Switch between providers by changing LLM_PROVIDER.
    # "deepseek" → development / cost-effective testing
    # "anthropic" → production / final testing
    # NO other code changes needed when switching.
    llm_provider: Literal["anthropic", "deepseek"] = "deepseek"

    # Anthropic / Claude
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"

    # DeepSeek
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"         # deepseek-chat = DeepSeek-V3
    deepseek_base_url: str = "https://api.deepseek.com"
    # Note: deepseek-reasoner = DeepSeek-R1 (better reasoning, slower)
    # Switch to deepseek-reasoner for complex name ambiguity resolution if needed.

    # LLM call limits — same regardless of provider (Section 3.7)
    llm_max_tokens: int = 1000
    llm_subgraph_max_nodes: int = 100   # Hard cap — spec Section 3.7
    llm_subgraph_max_edges: int = 200   # Hard cap — spec Section 3.7

    # ── Embedding ──────────────────────────────────────────────
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    # ── Joern CPG service ──────────────────────────────────────
    joern_host: str = "localhost"
    joern_port: int = 8080

    # ── Track 2 defaults (configurable per tenant) ─────────────
    # Spec Section 7.6 Step 8 — "configurable in system config, not hardcoded"
    finding_confidence_threshold: float = 0.70
    staleness_window_days: int = 30
    review_queue_sla_days: int = 5
    review_queue_escalation_interval_days: int = 5
    may_mean_suspension_threshold: float = 0.25

    # ── Coverage Gap Report threshold (Section 4.3) ────────────
    stub_node_threshold_days: int = 30

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        if v not in ("anthropic", "deepseek"):
            raise ValueError(f"LLM_PROVIDER must be 'anthropic' or 'deepseek', got: '{v}'")
        return v

    @property
    def joern_url(self) -> str:
        return f"http://{self.joern_host}:{self.joern_port}"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def active_llm_model(self) -> str:
        """The model name that is currently active based on LLM_PROVIDER."""
        if self.llm_provider == "anthropic":
            return self.anthropic_model
        return self.deepseek_model

    @property
    def active_llm_api_key(self) -> str:
        """The API key for the currently active LLM provider."""
        if self.llm_provider == "anthropic":
            return self.anthropic_api_key
        return self.deepseek_api_key


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton. Import and call this everywhere."""
    return Settings()
