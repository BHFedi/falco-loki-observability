"""
config.py — Runtime configuration loader.
Reads environment variables and mapping JSON files at startup (and on reload).
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, str(default)).strip().lower()
    return val in ("1", "true", "yes")


def _env_int(key: str, default: int = 1) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _load_json(path: str, label: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    with open(p) as f:
        data = json.load(f)
    log.info("Loaded %s from %s", label, path)
    return data


@dataclass
class Config:
    # ── Directories ──────────────────────────────────────────────────────────
    rules_dir: Path = field(default_factory=lambda: Path(_env("SIGMA_RULES_DIR", "/app/rules")))
    state_dir: Path = field(default_factory=lambda: Path(_env("SIGMA_STATE_DIR", "/app/state")))
    failed_dir: Path = field(default_factory=lambda: Path(_env("SIGMA_FAILED_DIR", "/app/failed")))

    # ── Watcher behaviour ────────────────────────────────────────────────────
    poll_interval: int = field(default_factory=lambda: _env_int("SIGMA_POLL_INTERVAL", 5))
    dedup_strategy: str = field(default_factory=lambda: _env("SIGMA_DEDUP_STRATEGY", "sha256"))
    fail_on_invalid: bool = field(default_factory=lambda: _env_bool("SIGMA_FAIL_ON_INVALID", True))

    # ── Backend / output ─────────────────────────────────────────────────────
    # FIX: default changed to grafana_alerting to match docker-compose
    output_format: str = field(default_factory=lambda: _env("SIGMA_OUTPUT_FORMAT", "grafana_alerting"))
    add_line_filters: bool = field(default_factory=lambda: _env_bool("SIGMA_ADD_LINE_FILTERS", True))
    case_sensitive: bool = field(default_factory=lambda: _env_bool("SIGMA_CASE_SENSITIVE", False))
    normalization_profile: str = field(default_factory=lambda: _env("NORMALIZATION_PROFILE", "falco_loki"))

    # ── Loki ruler deployment ────────────────────────────────────────────────
    loki_url: str = field(default_factory=lambda: _env("LOKI_URL", "http://loki:3100"))
    loki_ruler_path: str = field(default_factory=lambda: _env("LOKI_RULER_PATH", "/loki/api/v1/rules"))
    loki_group_by_field: str = field(default_factory=lambda: _env("LOKI_GROUP_BY_FIELD", "hostname"))
    loki_tenant: str = field(default_factory=lambda: _env("LOKI_TENANT_ID", "fake"))

    # ── Grafana alerting deployment ──────────────────────────────────────────
    grafana_url: str = field(default_factory=lambda: _env("GRAFANA_URL", "http://grafana:3000"))
    grafana_datasource_uid: str = field(default_factory=lambda: _env("GRAFANA_DATASOURCE_UID", "loki"))
    grafana_folder: str = field(default_factory=lambda: _env("GRAFANA_FOLDER", "security"))
    grafana_org_id: int = field(default_factory=lambda: _env_int("GRAFANA_ORG_ID", 1))
    grafana_interval: str = field(default_factory=lambda: _env("GRAFANA_INTERVAL", "1m"))
    grafana_contact_point: str = field(default_factory=lambda: _env("GRAFANA_CONTACT_POINT", "default"))
    grafana_api_key_file: str = field(default_factory=lambda: _env("GRAFANA_API_KEY_FILE", ""))

    # Basic-auth fallback for testing (used when no API key is present)
    grafana_user: str = field(default_factory=lambda: _env("GRAFANA_USER", "admin"))
    grafana_password: str = field(default_factory=lambda: _env("GRAFANA_PASSWORD", "admin"))

    # ── Mapping file paths ───────────────────────────────────────────────────
    field_map_file: str = field(default_factory=lambda: _env("SIGMA_FIELD_MAP_FILE", "/app/config/field_mapping.json"))
    label_map_file: str = field(default_factory=lambda: _env("SIGMA_LABEL_MAP_FILE", "/app/config/label_mapping.json"))

    # ── Loaded mapping data (populated by load_mappings()) ───────────────────
    field_mapping: dict = field(default_factory=dict)
    label_mapping: dict = field(default_factory=dict)

    # ── Grafana API key (loaded from file if specified) ───────────────────────
    grafana_api_key: str = ""

    def load_mappings(self) -> None:
        """Load field and label mapping JSON files. Call once at startup."""
        self.field_mapping = _load_json(self.field_map_file, "field_mapping")
        self.label_mapping = _load_json(self.label_map_file, "label_mapping")

        if self.grafana_api_key_file:
            key_path = Path(self.grafana_api_key_file)
            if key_path.exists():
                val = key_path.read_text().strip()
                if val:
                    self.grafana_api_key = val
                    log.info("Loaded Grafana API key from %s", self.grafana_api_key_file)
                else:
                    log.warning(
                        "GRAFANA_API_KEY_FILE (%s) is empty — will fall back to basic auth",
                        self.grafana_api_key_file,
                    )
            else:
                log.warning(
                    "GRAFANA_API_KEY_FILE set but file not found: %s — will fall back to basic auth",
                    self.grafana_api_key_file,
                )

    def ensure_dirs(self) -> None:
        for d in (self.rules_dir, self.state_dir, self.failed_dir):
            d.mkdir(parents=True, exist_ok=True)

    @property
    def loki_ruler_url(self) -> str:
        return self.loki_url.rstrip("/") + self.loki_ruler_path

    @property
    def grafana_alert_url(self) -> str:
        return self.grafana_url.rstrip("/") + "/api/v1/provisioning/alert-rules"

    @property
    def grafana_folder_url(self) -> str:
        return self.grafana_url.rstrip("/") + "/api/folders"

    def grafana_headers(self, content_type: str = "application/json") -> dict[str, str]:
        """
        Build Grafana request headers.
        Priority: Bearer token (service-account key) → Basic auth fallback.
        content_type lets callers override for YAML payloads.
        """
        headers: dict[str, str] = {"Content-Type": content_type}
        if self.grafana_api_key:
            headers["Authorization"] = f"Bearer {self.grafana_api_key}"
        else:
            # Basic auth fallback — fine for local/testing deployments
            import base64
            creds = base64.b64encode(
                f"{self.grafana_user}:{self.grafana_password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
            log.debug("Using Basic auth for Grafana (%s)", self.grafana_user)
        return headers

    # Convenience: extract the preferred field name for a Sigma field key
    def preferred_field(self, sigma_field: str) -> str | None:
        canonical = self.field_mapping.get("canonical_fields", {})
        entry = canonical.get(sigma_field)
        if not entry:
            return None
        preferred = entry.get("preferred", [])
        return preferred[0] if preferred else None

    # Convenience: resolve a Sigma label key to its preferred Loki label
    def preferred_label(self, sigma_label: str) -> str | None:
        aliases = self.label_mapping.get("label_aliases", {})
        entry = aliases.get(sigma_label)
        if not entry:
            return None
        return entry.get("preferred")

    def __repr__(self) -> str:  # pragma: no cover
        auth = "key" if self.grafana_api_key else f"basic:{self.grafana_user}"
        return (
            f"<Config output={self.output_format} loki={self.loki_url} "
            f"grafana={self.grafana_url} auth={auth} profile={self.normalization_profile}>"
        )
