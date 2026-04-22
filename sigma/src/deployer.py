"""
deployer.py — RuleDeployer

Grafana provisioning API (grafana_alerting format):
  POST /api/v1/provisioning/alert-rules
  Content-Type: application/json
  Authorization: Basic <base64> | Bearer <service-account-token>
  Body: single alert rule JSON object (Grafana's AlertRule schema)

Loki ruler API (ruler format):
  POST /loki/api/v1/rules
  Content-Type: application/json
  X-Scope-OrgID: fake
  Body: { namespace, groups: [{ name, interval, rules: [...] }] }

Key points:
  - grafana_alerting output from pySigma is a list of dicts — must POST each one
  - Grafana folder must exist before posting alert rules
  - Content-Type is always application/json for both targets
  - Backtick regex in Loki exprs replaced with double-quoted strings
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


# ── Grafana alerting payload extraction ───────────────────────────────────────

def _extract_grafana_rules(grafana_raw) -> list[dict]:
    """
    pySigma grafana_alerting output is a list of alert-rule dicts
    (or occasionally a YAML string). Normalise to list[dict].
    Each dict is posted individually to /api/v1/provisioning/alert-rules.
    """
    if isinstance(grafana_raw, list):
        rules = []
        for item in grafana_raw:
            if isinstance(item, dict):
                rules.append(item)
            elif isinstance(item, str):
                try:
                    parsed = yaml.safe_load(item)
                    if isinstance(parsed, dict):
                        rules.append(parsed)
                    elif isinstance(parsed, list):
                        rules.extend(p for p in parsed if isinstance(p, dict))
                except yaml.YAMLError:
                    log.warning("Could not parse grafana rule string: %.200r", item)
        return rules
    if isinstance(grafana_raw, dict):
        return [grafana_raw]
    if isinstance(grafana_raw, str):
        try:
            parsed = yaml.safe_load(grafana_raw)
            if isinstance(parsed, list):
                return [p for p in parsed if isinstance(p, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except yaml.YAMLError as exc:
            log.error("Could not parse grafana_yaml string: %s", exc)
    return []


# ── JSON payload builder (Loki ruler) ────────────────────────────────────────

def _build_ruler_payload(namespace: str, group_name: str, rules: list[dict], interval: str = "1m") -> dict:
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
        # Cache of folder UIDs we've already ensured exist
        self._ensured_folders: set[str] = set()

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
                json=payload,
                headers={"X-Scope-OrgID": self._config.loki_tenant},
                timeout=_HTTP_TIMEOUT,
            )
            if not resp.ok:
                log.error("Ruler HTTP %s for '%s': %s", resp.status_code, title, resp.text[:500])
                return False
            log.info("✓ Ruler '%s' → %s/%s [HTTP %s]", title, namespace, group, resp.status_code)
            return True
        except requests.RequestException as exc:
            log.error("Ruler network error for '%s': %s", title, exc)
            return False

    # ── Grafana alerting ──────────────────────────────────────────────────────

    def _ensure_grafana_folder(self, folder_title: str) -> str | None:
        """
        Create the Grafana folder if it doesn't exist yet.
        Returns the folder UID on success, None on failure.
        Caches successful lookups so we only call the API once per folder per run.
        """
        if folder_title in self._ensured_folders:
            return folder_title  # already confirmed to exist

        url = self._config.grafana_folder_url
        headers = self._config.grafana_headers("application/json")

        # Check if it already exists
        try:
            resp = self._session.get(url, headers=headers, timeout=_HTTP_TIMEOUT)
            if resp.ok:
                for f in resp.json():
                    if f.get("title") == folder_title:
                        uid = f.get("uid", folder_title)
                        self._ensured_folders.add(folder_title)
                        log.debug("Grafana folder '%s' already exists (uid=%s)", folder_title, uid)
                        return uid
        except requests.RequestException as exc:
            log.warning("Could not list Grafana folders: %s", exc)

        # Create it
        try:
            resp = self._session.post(
                url,
                json={"title": folder_title},
                headers=headers,
                timeout=_HTTP_TIMEOUT,
            )
            if resp.ok:
                uid = resp.json().get("uid", folder_title)
                self._ensured_folders.add(folder_title)
                log.info("Created Grafana folder '%s' (uid=%s)", folder_title, uid)
                return uid
            log.warning(
                "Could not create Grafana folder '%s': HTTP %s %s",
                folder_title, resp.status_code, resp.text[:200],
            )
        except requests.RequestException as exc:
            log.warning("Network error creating Grafana folder '%s': %s", folder_title, exc)

        return None

    def _deploy_grafana(self, rule: dict, grafana_raw) -> bool:
        """
        Deploy one or more Grafana alert rules extracted from pySigma output.

        pySigma grafana_alerting backend returns a list[dict] where each dict
        is a complete Grafana AlertRule JSON object. We POST them individually
        to /api/v1/provisioning/alert-rules (Content-Type: application/json).

        FIX: Previous code sent raw YAML with Content-Type: application/yaml,
        which is not accepted by the provisioning API. The endpoint only accepts JSON.
        """
        title = rule.get("title", "unknown")

        # Ensure the target folder exists before posting rules into it
        folder_uid = self._ensure_grafana_folder(self._config.grafana_folder)
        if folder_uid is None:
            log.warning(
                "Grafana folder '%s' could not be ensured — alert rules may be rejected",
                self._config.grafana_folder,
            )

        grafana_rules = _extract_grafana_rules(grafana_raw)
        if not grafana_rules:
            log.warning("No parseable Grafana alert rules for '%s'", title)
            return False

        url = self._config.grafana_alert_url
        # FIX: Content-Type must be application/json for the provisioning API
        headers = self._config.grafana_headers("application/json")

        all_ok = True
        for idx, alert_rule in enumerate(grafana_rules):
            # Inject/override the folder UID so rules land in the right folder
            if folder_uid:
                alert_rule["folderUID"] = folder_uid

            log.debug(
                "Grafana POST rule %d/%d for '%s':\n%s",
                idx + 1, len(grafana_rules), title,
                json.dumps(alert_rule, indent=2),
            )
            try:
                resp = self._session.post(
                    url, json=alert_rule, headers=headers, timeout=_HTTP_TIMEOUT,
                )
                if not resp.ok:
                    log.error(
                        "Grafana HTTP %s for '%s' (rule %d): %s",
                        resp.status_code, title, idx + 1, resp.text[:500],
                    )
                    all_ok = False
                else:
                    log.info(
                        "✓ Grafana rule %d/%d '%s' → folder=%s [HTTP %s]",
                        idx + 1, len(grafana_rules), title,
                        self._config.grafana_folder, resp.status_code,
                    )
            except requests.RequestException as exc:
                log.error("Grafana network error for '%s' (rule %d): %s", title, idx + 1, exc)
                all_ok = False

        return all_ok

    def close(self) -> None:
        self._session.close()
