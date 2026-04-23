"""
deployer.py — RuleDeployer

pySigma grafana_alerting backend produces a YAML string in the Grafana
*provisioning file* format (apiVersion: 1 / groups / rules).  That format
is NOT accepted by the REST API at /api/v1/provisioning/alert-rules.

The REST API expects one JSON object per rule shaped like:
  {
    "title":        str,
    "condition":    "A",
    "folderUID":    str,
    "ruleGroup":    str,
    "orgID":        int,
    "for":          str,          # e.g. "0s"
    "noDataState":  str,
    "execErrState": str,
    "annotations":  {str: str},
    "labels":       {str: str},
    "isPaused":     bool,
    "data": [{
      "refId":             "A",
      "queryType":         "instant",
      "relativeTimeRange": {"from": 600, "to": 0},
      "datasourceUid":     str,
      "model": {
        "expr":          str,
        "refId":         "A",
        "editorMode":    "code",
        "instant":       true,
        "intervalMs":    1000,
        "maxDataPoints": 43200,
        "queryType":     "instant",
        "direction":     "backward"
      }
    }]
  }

This module parses the pySigma YAML string and builds the correct payload.
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


# ── Slug helpers ──────────────────────────────────────────────────────────────

def _safe_slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9_-]", "_", str(text).lower()).strip("_")[:64]
    return s or "sigma"


# ── backtick fix ──────────────────────────────────────────────────────────────

def _fix_backtick_expr(expr: str) -> str:
    """
    Replace LogQL backtick regex literals with double-quoted strings.
    Backticks allow literal strings (no escape processing).
    When converting to double-quoted strings we must:
      1. Remove backslashes before chars that don't need escaping in regex
         (spaces, hyphens, forward slashes that were escaped for no reason)
      2. Escape any actual double-quote chars inside the regex
    """
    def replacer(m: re.Match) -> str:
        inner = m.group(1)
        # Remove unnecessary backslash escapes that are valid unescaped in regex:
        # \  (space), \-, \/, \_ and other non-special chars
        inner = re.sub(r'\\([ \-/_])', r'\1', inner)
        # Now escape any literal double quotes
        inner = inner.replace('"', '\\"')
        return f'"{inner}"'
    return re.sub(r'`([^`]*)`', replacer, expr)

# ── pySigma provisioning YAML → raw rule dicts ───────────────────────────────

def _parse_provisioning_yaml(grafana_raw) -> list[dict]:
    """
    Parse pySigma grafana_alerting output into a flat list of rule dicts
    as they appear inside groups[].rules[] of the provisioning YAML.

    pySigma output (confirmed from debug_convert.py):
      apiVersion: 1
      groups:
        - orgId: 1
          name: 1m
          folder: security
          interval: 1m
          rules:
            - uid: ...
              title: ...
              condition: A
              data: [...]           ← already has the correct Grafana query model
              noDataState: OK
              execErrState: OK
              annotations: {...}
              labels: {...}
              isPaused: false
              notification_settings: {receiver: default}
    """
    if isinstance(grafana_raw, list):
        yaml_str = "\n---\n".join(
            item if isinstance(item, str)
            else yaml.dump(item, default_flow_style=False)
            for item in grafana_raw
        )
    elif isinstance(grafana_raw, str):
        yaml_str = grafana_raw
    else:
        yaml_str = str(grafana_raw)

    raw_rules: list[dict] = []
    try:
        for doc in yaml.safe_load_all(yaml_str):
            if not doc or not isinstance(doc, dict):
                continue
            for group in doc.get("groups", []):
                if not isinstance(group, dict):
                    continue
                group_name = group.get("name", "sigma")
                for r in group.get("rules", []):
                    if isinstance(r, dict):
                        r["_group_name"] = group_name
                        raw_rules.append(r)
    except yaml.YAMLError as exc:
        log.error("Failed to parse pySigma provisioning YAML: %s", exc)

    log.debug("Parsed %d rule(s) from provisioning YAML", len(raw_rules))
    return raw_rules


def _build_rest_payload(
    pysigma_rule: dict,
    folder_uid: str,
    org_id: int,
) -> dict | None:
    """
    Translate one pySigma provisioning-format rule dict into the JSON payload
    expected by POST /api/v1/provisioning/alert-rules.

    The pySigma rule already contains a data[] array with the correct Grafana
    query model — we just need to wrap it with the top-level REST fields and
    inject folderUID / orgID / ruleGroup.
    """
    title = pysigma_rule.get("title", "sigma_rule")
    condition = pysigma_rule.get("condition", "A")
    data = pysigma_rule.get("data", [])

    if not data:
        log.warning("Rule '%s' has no data[] — skipping", title)
        return None

    # Sanitize exprs: backticks are valid LogQL but break JSON serialisation
    clean_data = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        entry = dict(entry)
        model = dict(entry.get("model", {}))
        if "expr" in model:
            model["expr"] = _fix_backtick_expr(str(model["expr"]))
        entry["model"] = model
        clean_data.append(entry)

    if not clean_data:
        log.warning("Rule '%s' has no valid data entries after cleaning — skipping", title)
        return None

    payload: dict = {
        "title":        title,
        "condition":    condition,
        "folderUID":    folder_uid,
        "ruleGroup":    pysigma_rule.get("_group_name", "sigma"),
        "orgID":        org_id,
        "for":          pysigma_rule.get("for", "0s"),
        "noDataState":  pysigma_rule.get("noDataState", "OK"),
        "execErrState": pysigma_rule.get("execErrState", "OK"),
        "annotations":  pysigma_rule.get("annotations") or {},
        "labels":       pysigma_rule.get("labels") or {},
        "isPaused":     bool(pysigma_rule.get("isPaused", False)),
        "data":         clean_data,
    }

    # Preserve pySigma-generated UID so Grafana can deduplicate on re-push
    uid = pysigma_rule.get("uid")
    if uid:
        payload["uid"] = uid

    # notification_settings intentionally omitted — contact points are optional.
    # Grafana accepts rules without them and uses its default routing policy.
    # To wire up a contact point later, set GRAFANA_CONTACT_POINT in docker-compose
    # and uncomment:
    #   ns = pysigma_rule.get("notification_settings")
    #   if ns and config.grafana_contact_point:
    #       payload["notification_settings"] = ns

    return payload


# ── RuleDeployer ──────────────────────────────────────────────────────────────

class RuleDeployer:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = requests.Session()
        self._folder_uid_cache: dict[str, str] = {}

    def deploy(self, rule: dict, result: ConversionResult) -> dict[str, bool]:
        outcomes: dict[str, bool] = {}
        log.info("Deploying '%s'", rule.get("title"))

        if result.grafana_yaml:
            outcomes["grafana"] = self._deploy_grafana(rule, result.grafana_yaml)
        return outcomes

    # ── Folder management ─────────────────────────────────────────────────────

    def _ensure_folder(self, folder_title: str) -> str | None:
        """
        Return the UID of the Grafana folder, creating it if needed.
        Tries to create with uid = slug(folder_title) for stability.
        Result is cached for the lifetime of this deployer instance.
        """
        if folder_title in self._folder_uid_cache:
            return self._folder_uid_cache[folder_title]

        headers = self._config.grafana_headers("application/json")
        list_url = self._config.grafana_url.rstrip("/") + "/api/folders"

        # Check if it already exists (by title or by uid)
        try:
            resp = self._session.get(list_url, headers=headers, timeout=_HTTP_TIMEOUT)
            if resp.ok:
                for f in resp.json():
                    if f.get("title") == folder_title or f.get("uid") == folder_title:
                        uid = f["uid"]
                        self._folder_uid_cache[folder_title] = uid
                        log.debug("Folder '%s' already exists uid=%s", folder_title, uid)
                        return uid
        except requests.RequestException as exc:
            log.warning("Could not list Grafana folders: %s", exc)

        # Create it with a stable, predictable UID
        desired_uid = _safe_slug(folder_title)
        try:
            resp = self._session.post(
                list_url,
                json={"title": folder_title, "uid": desired_uid},
                headers=headers,
                timeout=_HTTP_TIMEOUT,
            )
            if resp.ok:
                uid = resp.json().get("uid", desired_uid)
                self._folder_uid_cache[folder_title] = uid
                log.info("Created Grafana folder '%s' uid=%s", folder_title, uid)
                return uid
            log.warning(
                "Could not create folder '%s': HTTP %s %s",
                folder_title, resp.status_code, resp.text[:300],
            )
        except requests.RequestException as exc:
            log.warning("Network error creating folder '%s': %s", folder_title, exc)

        return None

    # ── Grafana REST deploy ───────────────────────────────────────────────────

    def _deploy_grafana(self, rule: dict, grafana_raw) -> bool:
        title = rule.get("title", "unknown")

        folder_uid = self._ensure_folder(self._config.grafana_folder)
        if not folder_uid:
            log.error(
                "Cannot deploy '%s': folder '%s' could not be ensured",
                title, self._config.grafana_folder,
            )
            return False

        raw_rules = _parse_provisioning_yaml(grafana_raw)
        if not raw_rules:
            log.warning("No rules parsed from pySigma output for '%s'", title)
            return False

        payloads = []
        for r in raw_rules:
            p = _build_rest_payload(r, folder_uid=folder_uid, org_id=self._config.grafana_org_id)
            if p:
                payloads.append(p)

        if not payloads:
            log.warning("No valid REST payloads built for '%s'", title)
            return False

        url = self._config.grafana_alert_url
        headers = self._config.grafana_headers("application/json")
        all_ok = True

        for idx, payload in enumerate(payloads):
            log.debug(
                "POST rule %d/%d '%s' to %s:\n%s",
                idx + 1, len(payloads), title, url,
                json.dumps(payload, indent=2),
            )
            try:
                resp = self._session.post(url, json=payload, headers=headers, timeout=_HTTP_TIMEOUT)
                if resp.ok:
                    returned_uid = resp.json().get("uid", "?")
                    log.info(
                        "✓ Grafana '%s' → folder=%s group=%s uid=%s [HTTP %s]",
                        title, self._config.grafana_folder,
                        payload["ruleGroup"], returned_uid, resp.status_code,
                    )
                else:
                    log.error(
                        "Grafana HTTP %s for '%s' (rule %d/%d): %s",
                        resp.status_code, title, idx + 1, len(payloads), resp.text[:500],
                    )
                    all_ok = False
            except requests.RequestException as exc:
                log.error("Network error posting '%s': %s", title, exc)
                all_ok = False

        return all_ok

    def close(self) -> None:
        self._session.close()
