"""
config.py — Runtime configuration loader.
Reads environment variables and mapping JSON files at startup (and on reload).
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    output_format: str = field(default_factory=lambda: _env("SIGMA_OUTPUT_FORMAT", "ruler"))
    add_line_filters: bool = field(default_factory=lambda: _env_bool("SIGMA_ADD_LINE_FILTERS", True))
    case_sensitive: bool = field(default_factory=lambda: _env_bool("SIGMA_CASE_SENSITIVE", False))
    normalization_profile: str = field(default_factory=lambda: _env("NORMALIZATION_PROFILE", "falco_loki"))

    # ── Loki ruler deployment ────────────────────────────────────────────────
    loki_url: str = field(default_factory=lambda: _env("LOKI_URL", "http://loki:3100"))
    loki_ruler_path: str = field(default_factory=lambda: _env("LOKI_RULER_PATH", "/loki/api/v1/rules"))
    loki_group_by_field: str = field(default_factory=lambda: _env("LOKI_GROUP_BY_FIELD", "hostname"))

    # ── Grafana alerting deployment ──────────────────────────────────────────
    grafana_url: str = field(default_factory=lambda: _env("GRAFANA_URL", "http://grafana:3000"))
    grafana_datasource_uid: str = field(default_factory=lambda: _env("GRAFANA_DATASOURCE_UID", "loki"))
    grafana_folder: str = field(default_factory=lambda: _env("GRAFANA_FOLDER", "security"))
    grafana_org_id: int = field(default_factory=lambda: _env_int("GRAFANA_ORG_ID", 1))
    grafana_interval: str = field(default_factory=lambda: _env("GRAFANA_INTERVAL", "1m"))
    grafana_contact_point: str = field(default_factory=lambda: _env("GRAFANA_CONTACT_POINT", "default"))
    grafana_api_key_file: str = field(default_factory=lambda: _env("GRAFANA_API_KEY_FILE", ""))

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
                self.grafana_api_key = key_path.read_text().strip()
                log.info("Loaded Grafana API key from %s", self.grafana_api_key_file)
            else:
                log.warning("GRAFANA_API_KEY_FILE set but file not found: %s", self.grafana_api_key_file)

    def ensure_dirs(self) -> None:
        for d in (self.rules_dir, self.state_dir, self.failed_dir):
            d.mkdir(parents=True, exist_ok=True)

    @property
    def loki_ruler_url(self) -> str:
        return self.loki_url.rstrip("/") + self.loki_ruler_path

    @property
    def grafana_alert_url(self) -> str:
        return self.grafana_url.rstrip("/") + "/api/v1/provisioning/alert-rules"

    def grafana_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.grafana_api_key:
            headers["Authorization"] = f"Bearer {self.grafana_api_key}"
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
        return (
            f"<Config output={self.output_format} loki={self.loki_url} "
            f"grafana={self.grafana_url} profile={self.normalization_profile}>"
        )
