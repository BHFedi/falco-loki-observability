"""
deployer.py — RuleDeployer

Packages converted rules into the correct API payload and pushes them to:
  - Loki ruler API   (POST /loki/api/v1/rules/{namespace})
  - Grafana alerting provisioning API  (POST /api/v1/provisioning/alert-rules)

Namespace and group assignment is deterministic, derived from logsource,
severity, and MITRE ATT&CK tags in the rule.
"""

import hashlib
import logging
import re
from typing import Any

import requests
import yaml

from config import Config
from converter import ConversionResult

log = logging.getLogger(__name__)

# Timeouts for HTTP calls
_HTTP_TIMEOUT = 15


def _safe_slug(text: str) -> str:
    """Convert arbitrary text to a safe lowercase slug."""
    return re.sub(r"[^a-z0-9_-]", "_", text.lower()).strip("_")[:64]


def _derive_namespace(rule: dict) -> str:
    """
    Deterministic namespace from logsource.product + category.
    Falls back to 'sigma_generic'.
    """
    logsource = rule.get("logsource", {})
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    parts = [p for p in (product, category) if p]
    return _safe_slug("_".join(parts)) if parts else "sigma_generic"


def _derive_group(rule: dict) -> str:
    """
    Deterministic group name: prefer MITRE tactic tag, then severity, then title slug.
    """
    tags: list = rule.get("tags", []) or []
    for tag in tags:
        tag_l = tag.lower()
        if tag_l.startswith("attack.ta"):
            return _safe_slug(tag_l.replace("attack.", ""))
    level = rule.get("level", "medium")
    return f"severity_{_safe_slug(level)}"


def _parse_ruler_yaml(ruler_yaml: str) -> list[dict]:
    """
    Parse pySigma ruler output (one or more YAML docs) into a list of
    {'namespace': str, 'group': str, 'rule': dict} records.
    """
    docs = list(yaml.safe_load_all(ruler_yaml))
    parsed = []
    for doc in docs:
        if not doc:
            continue
        # pySigma ruler format: top-level is a dict with group info
        # Shape: {groups: [{name: ..., rules: [...]}]}
        if "groups" in doc:
            for group in doc["groups"]:
                for rule_item in group.get("rules", []):
                    parsed.append({
                        "group": group.get("name", "sigma"),
                        "rule": rule_item,
                    })
        else:
            # Flat rule dict
            parsed.append({"group": "sigma", "rule": doc})
    return parsed


class RuleDeployer:
    """
    Encapsulates deployment logic for both Loki ruler and Grafana alerting targets.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    # ── Public entry point ────────────────────────────────────────────────────

    def deploy(self, rule: dict, result: ConversionResult) -> dict[str, bool]:
        """
        Deploy a converted rule.
        Returns {'ruler': bool, 'grafana': bool} indicating success per target.
        """
        outcomes: dict[str, bool] = {}

        namespace = _derive_namespace(rule)
        group = _derive_group(rule)

        if result.ruler_yaml:
            outcomes["ruler"] = self._deploy_ruler(rule, result.ruler_yaml, namespace, group)

        if result.grafana_yaml:
            outcomes["grafana"] = self._deploy_grafana(rule, result.grafana_yaml)

        return outcomes

    # ── Loki ruler deployment ─────────────────────────────────────────────────

    def _deploy_ruler(
        self,
        rule: dict,
        ruler_yaml: str,
        namespace: str,
        group: str,
    ) -> bool:
        """
        Package ruler YAML into the Loki ruler API format and POST it.

        Loki ruler API expects:
          POST /loki/api/v1/rules/{namespace}
          Content-Type: application/yaml
          Body: YAML with shape:
            name: <group>
            rules:
              - alert: <name>
                expr: <logql>
                ...
        """
        url = f"{self._config.loki_ruler_url}/{namespace}"
        title = rule.get("title", "unknown")
        level = rule.get("level", "medium")
        description = rule.get("description", title)
        tags = rule.get("tags", [])

        # Build a canonical ruler payload from pySigma output or raw rule
        try:
            parsed = _parse_ruler_yaml(ruler_yaml)
        except Exception as exc:
            log.warning("Could not parse ruler YAML for '%s': %s — using raw", title, exc)
            parsed = []

        if parsed:
            # Use the first parsed rule's expr; combine all rules into one group
            rules_payload = []
            for item in parsed:
                r = item.get("rule", {})
                rules_payload.append(r)
        else:
            # Fallback: best-effort extract from raw YAML
            rules_payload = [{"alert": _safe_slug(title), "expr": ruler_yaml}]

        payload = yaml.dump(
            {
                "name": group,
                "rules": rules_payload,
            },
            default_flow_style=False,
            allow_unicode=True,
        )

        try:
            resp = self._session.post(
                url,
                data=payload,
                headers={"Content-Type": "application/yaml"},
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            log.info(
                "Deployed ruler rule '%s' → %s/%s [HTTP %s]",
                title, namespace, group, resp.status_code,
            )
            return True
        except requests.RequestException as exc:
            log.error("Ruler deployment failed for '%s': %s", title, exc)
            return False

    # ── Grafana alerting deployment ───────────────────────────────────────────

    def _deploy_grafana(self, rule: dict, grafana_yaml: str) -> bool:
        """
        POST Grafana alerting provisioning YAML to Grafana's provisioning API.
        """
        title = rule.get("title", "unknown")
        url = self._config.grafana_alert_url
        headers = self._config.grafana_headers()
        headers["Content-Type"] = "application/yaml"

        try:
            resp = self._session.post(
                url,
                data=grafana_yaml,
                headers=headers,
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            log.info(
                "Deployed Grafana alert '%s' → folder=%s [HTTP %s]",
                title, self._config.grafana_folder, resp.status_code,
            )
            return True
        except requests.RequestException as exc:
            log.error("Grafana deployment failed for '%s': %s", title, exc)
            return False

    def close(self) -> None:
        self._session.close()
