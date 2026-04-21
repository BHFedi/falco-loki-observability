"""
deployer.py — RuleDeployer

Loki ruler API (confirmed working):
  POST /loki/api/v1/rules
  Content-Type: application/json
  X-Scope-OrgID: fake
  Body:
    {
      "namespace": "linux_process_creation",
      "groups": [{
        "name": "ta0004",
        "interval": "1m",
        "rules": [{
          "alert": "Suspicious_Sudo_Usage",
          "expr": "sum(count_over_time(...)[1m]) or vector(0) > 0",
          "for": "0m",
          "labels": {"severity": "high"},
          "annotations": {"summary": "..."}
        }]
      }]
    }

Key points:
  - Always POST to /loki/api/v1/rules (no namespace in path)
  - namespace lives inside the JSON body
  - X-Scope-OrgID header is required (even with auth_enabled: false)
  - Content-Type: application/json
  - No YAML for Loki deployment — pure JSON
  - Backtick regex in expr replaced with double-quoted strings
    (backticks are LogQL syntax but break JSON serialization)
"""

import json
import logging
import re

import requests
import yaml

from config import Config
from converter import ConversionResult

log = logging.getLogger(__name__)

_HTTP_TIMEOUT = 15


# ── Slug / namespace / group helpers ──────────────────────────────────────────

def _safe_slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9_-]", "_", str(text).lower()).strip("_")[:64]
    return s or "sigma"


def _derive_namespace(rule: dict) -> str:
    logsource = rule.get("logsource", {})
    product = _safe_slug(logsource.get("product", ""))
    category = _safe_slug(logsource.get("category", ""))
    parts = [p for p in (product, category) if p]
    return "_".join(parts) if parts else "sigma_generic"


def _derive_group(rule: dict) -> str:
    for tag in (rule.get("tags", []) or []):
        if tag.lower().startswith("attack.ta"):
            slug = _safe_slug(tag.lower().replace("attack.", ""))
            if slug:
                return slug
    return f"severity_{_safe_slug(rule.get('level', 'medium'))}"


# ── expr sanitization ─────────────────────────────────────────────────────────

def _fix_backtick_expr(expr: str) -> str:
    """
    Replace LogQL backtick-quoted regex literals with double-quoted strings.
    Backticks are valid LogQL but invalid JSON — Go's JSON parser rejects them.
      `(?i).*sudo.*`  →  "(?i).*sudo.*"
    """
    def replacer(m: re.Match) -> str:
        inner = m.group(1).replace('"', '\\"')
        return f'"{inner}"'
    return re.sub(r'`([^`]*)`', replacer, expr)


# ── pySigma ruler YAML → alert rule dicts ────────────────────────────────────

def _extract_alert_rules(ruler_raw) -> list[dict]:
    """
    Parse pySigma ruler output (str | list) and return flat list of
    alert rule dicts with backtick exprs converted to double-quoted strings.
    """
    if isinstance(ruler_raw, str):
        yaml_str = ruler_raw
    elif isinstance(ruler_raw, list):
        parts = []
        for item in ruler_raw:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(yaml.dump(item, default_flow_style=False))
            else:
                parts.append(str(item))
        yaml_str = "\n---\n".join(parts)
    else:
        yaml_str = str(ruler_raw)

    rules: list[dict] = []
    try:
        for doc in yaml.safe_load_all(yaml_str):
            if not doc or not isinstance(doc, dict):
                continue
            for grp in doc.get("groups", []):
                if not isinstance(grp, dict):
                    continue
                for r in grp.get("rules", []):
                    if isinstance(r, dict) and "expr" in r:
                        r["expr"] = _fix_backtick_expr(r["expr"])
                        rules.append(r)
            # bare rule without groups wrapper
            if "alert" in doc and "expr" in doc and not doc.get("groups"):
                doc["expr"] = _fix_backtick_expr(doc["expr"])
                rules.append(doc)
    except yaml.YAMLError as exc:
        log.error("YAML parse error extracting rules: %s", exc)

    log.debug("Extracted %d alert rule(s)", len(rules))
    return rules


# ── JSON payload builder ──────────────────────────────────────────────────────

def _build_ruler_payload(namespace: str, group_name: str, rules: list[dict], interval: str = "1m") -> dict:
    """
    Build the JSON dict for POST /loki/api/v1/rules.
    namespace and groups[].name are both required non-empty strings.
    """
    assert namespace, "namespace must not be empty"
    assert group_name, "group_name must not be empty"
    return {
        "namespace": namespace,
        "groups": [{
            "name": group_name,
            "interval": interval,
            "rules": rules,
        }]
    }


def _fallback_rule(rule: dict) -> dict:
    title = rule.get("title", "sigma_alert")
    level = rule.get("level", "medium")
    safe = re.escape(title).replace('"', '\\"')
    return {
        "alert": _safe_slug(title),
        "expr": f'count_over_time({{source="falco"}} |~ "(?i){safe}" [5m]) > 0',
        "for": "0m",
        "labels": {"severity": level, "source": "sigma"},
        "annotations": {
            "summary": title,
            "description": rule.get("description", title),
        },
    }


# ── RuleDeployer ──────────────────────────────────────────────────────────────

class RuleDeployer:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = requests.Session()

    def deploy(self, rule: dict, result: ConversionResult) -> dict[str, bool]:
        outcomes: dict[str, bool] = {}
        namespace = _derive_namespace(rule)
        group = _derive_group(rule)
        log.info("Deploying '%s' → namespace=%s group=%s", rule.get("title"), namespace, group)

        if result.ruler_yaml:
            outcomes["ruler"] = self._deploy_ruler(rule, result.ruler_yaml, namespace, group)
        if result.grafana_yaml:
            outcomes["grafana"] = self._deploy_grafana(rule, result.grafana_yaml)
        return outcomes

    # ── Loki ruler (JSON, fixed endpoint, tenant header) ─────────────────────

    def _deploy_ruler(self, rule: dict, ruler_raw, namespace: str, group: str) -> bool:
        title = rule.get("title", "unknown")
        url = self._config.loki_url.rstrip("/") + "/loki/api/v1/rules"

        alert_rules = _extract_alert_rules(ruler_raw)
        if not alert_rules:
            log.warning("No parseable rules for '%s' — using fallback", title)
            alert_rules = [_fallback_rule(rule)]

        payload = _build_ruler_payload(namespace, group, alert_rules, self._config.grafana_interval)

        log.info(
            "Ruler POST %s  namespace=%s group=%s rules=%d\n%s",
            url, namespace, group, len(alert_rules),
            json.dumps(payload, indent=2),
        )

        try:
            resp = self._session.post(
                url,
                json=payload,                          # Content-Type: application/json
                headers={"X-Scope-OrgID": self._config.loki_tenant},
                timeout=_HTTP_TIMEOUT,
            )
            if not resp.ok:
                log.error(
                    "Ruler HTTP %s for '%s': %s",
                    resp.status_code, title, resp.text[:500],
                )
                return False
            log.info("✓ Ruler '%s' → %s/%s [HTTP %s]", title, namespace, group, resp.status_code)
            return True
        except requests.RequestException as exc:
            log.error("Ruler network error for '%s': %s", title, exc)
            return False

    # ── Grafana alerting ──────────────────────────────────────────────────────

    def _deploy_grafana(self, rule: dict, grafana_yaml: str) -> bool:
        title = rule.get("title", "unknown")
        url = self._config.grafana_alert_url
        headers = self._config.grafana_headers()
        headers["Content-Type"] = "application/yaml"
        try:
            resp = self._session.post(
                url, data=grafana_yaml, headers=headers, timeout=_HTTP_TIMEOUT,
            )
            if not resp.ok:
                log.error(
                    "Grafana HTTP %s for '%s': %s",
                    resp.status_code, title, resp.text[:500],
                )
                return False
            log.info(
                "✓ Grafana '%s' → folder=%s [HTTP %s]",
                title, self._config.grafana_folder, resp.status_code,
            )
            return True
        except requests.RequestException as exc:
            log.error("Grafana network error for '%s': %s", title, exc)
            return False

    def close(self) -> None:
        self._session.close()
