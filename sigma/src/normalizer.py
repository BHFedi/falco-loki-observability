"""
normalizer.py — Normalization engine.

Composed of:
  - FieldNormalizer  : translates Sigma detection fields to canonical Loki/Falco field names
  - LabelNormalizer  : aligns rule label semantics with the ingestion pipeline's label schema
  - NormalizationEngine : orchestrates both, driven by the loaded mapping config
"""

import copy
import logging
import re
from typing import Any

from config import Config

log = logging.getLogger(__name__)


class FieldNormalizer:
    """
    Applies field-level transformations to the Sigma detection block,
    translating Sigma field names into canonical log fields aligned with
    Loki JSON payloads (e.g. CommandLine → proc.cmdline).
    """

    def __init__(self, config: Config) -> None:
        self._canonical: dict = config.field_mapping.get("canonical_fields", {})
        self._norm_rules: dict = config.field_mapping.get("normalization_rules", {})
        self._keep_alias: bool = self._norm_rules.get("keep_original_field_name_as_alias", True)
        self._support_wildcards: bool = self._norm_rules.get("support_wildcards", True)
        self._wildcard_policy: dict = self._norm_rules.get("wildcard_policy", {
            "prefix": "startswith",
            "suffix": "endswith",
            "contains": "contains",
        })

    def _resolve_field(self, field_name: str) -> str:
        """
        Strip modifier suffixes (e.g. |contains, |startswith) before lookup,
        then return the preferred canonical field name or the original lowercased.
        """
        base = field_name.split("|")[0].strip()
        entry = self._canonical.get(base)
        if entry:
            preferred = entry.get("preferred", [])
            if preferred:
                return preferred[0]
        # No mapping: lowercase the raw field name
        return base.lower()

    def _normalize_value(self, value: Any, modifier: str = "") -> Any:
        """Apply wildcard-aware value normalization."""
        if not self._support_wildcards or not isinstance(value, str):
            return value
        return value  # wildcards are handled at query-build time by pySigma

    def _transform_detection_item(self, key: str, value: Any) -> tuple[str, Any]:
        """Return (new_key, new_value) for a single detection key/value pair."""
        # Split modifier from field name
        parts = key.split("|")
        base_field = parts[0].strip()
        modifiers = parts[1:] if len(parts) > 1 else []

        resolved = self._resolve_field(base_field)

        # Rebuild key with original modifiers preserved
        new_key = "|".join([resolved] + modifiers)

        if isinstance(value, list):
            new_value = [self._normalize_value(v) for v in value]
        else:
            new_value = self._normalize_value(value)

        return new_key, new_value

    def apply_field_mapping(self, rule: dict) -> dict:
        """
        Walk the detection block and translate Sigma fields to canonical names.
        Preserves the original structure; adds _field_aliases for compatibility
        when keep_original_field_name_as_alias is true.
        """
        rule = copy.deepcopy(rule)
        detection: dict = rule.get("detection", {})
        if not detection:
            return rule

        new_detection: dict = {}
        aliases: dict = {}

        for key, value in detection.items():
            if key == "condition":
                new_detection[key] = value
                continue

            if isinstance(value, dict):
                new_block: dict = {}
                for field_key, field_val in value.items():
                    new_field, new_val = self._transform_detection_item(field_key, field_val)
                    new_block[new_field] = new_val
                    # Record alias for compatibility
                    original_base = field_key.split("|")[0]
                    if self._keep_alias and original_base != new_field.split("|")[0]:
                        aliases[new_field.split("|")[0]] = original_base
                new_detection[key] = new_block
            elif isinstance(value, list):
                new_list = []
                for item in value:
                    if isinstance(item, dict):
                        new_item = {}
                        for field_key, field_val in item.items():
                            new_field, new_val = self._transform_detection_item(field_key, field_val)
                            new_item[new_field] = new_val
                        new_list.append(new_item)
                    else:
                        new_list.append(item)
                new_detection[key] = new_list
            else:
                new_detection[key] = value

        rule["detection"] = new_detection
        if aliases:
            rule.setdefault("_field_aliases", {}).update(aliases)

        return rule


class LabelNormalizer:
    """
    Aligns rule label semantics with the label schema produced by the
    ingestion pipeline (Falcosidekick + Alloy static labels → Loki streams).
    """

    def __init__(self, config: Config) -> None:
        self._label_aliases: dict = config.label_mapping.get("label_aliases", {})
        self._stream_labels: dict = config.label_mapping.get("stream_labels", {})
        self._alloy_static: dict = config.label_mapping.get("alloy_static_labels", {})
        self._falco_labels: list = config.label_mapping.get(
            "falcosidekick_loki_labels", {}
        ).get("extralabels", [])
        self._profile: str = config.normalization_profile
        self._policy: dict = config.label_mapping.get("label_generation_policy", {})

    def _preferred(self, sigma_key: str) -> str:
        """Resolve a Sigma label key to its preferred Loki label name."""
        entry = self._label_aliases.get(sigma_key, {})
        return entry.get("preferred", sigma_key.lower())

    def _known_stream_labels(self) -> set[str]:
        """Return the full set of labels that will be present in Loki streams."""
        known: set[str] = set()
        for group in self._stream_labels.values():
            known.update(group)
        known.update(self._alloy_static.keys())
        known.update(self._falco_labels)
        return known

    def apply_label_mapping(self, rule: dict) -> dict:
        """
        Inject _loki_labels into the rule dict: a set of labels the generated
        LogQL stream selector should target, based on policy and available labels.
        """
        rule = copy.deepcopy(rule)
        known = self._known_stream_labels()

        loki_labels: dict[str, str | None] = {}

        # Always include static Alloy labels in selector context
        for k, v in self._alloy_static.items():
            loki_labels[k] = v

        # Map rule-level attributes to their preferred Loki label names
        sigma_to_rule_attr: dict[str, str] = {
            "Source": "logsource",          # logsource.product / category → source label
            "Severity": "level",
            "Rule": "title",
            "Tags": "tags",
            "Hostname": None,               # runtime label, not in rule body
            "Container": None,
            "ProcessName": None,
        }

        for sigma_key, rule_attr in sigma_to_rule_attr.items():
            preferred = self._preferred(sigma_key)
            if preferred not in known:
                log.debug("Label %s not in known stream labels, skipping", preferred)
                continue

            if rule_attr and rule_attr in rule:
                val = rule[rule_attr]
                # logsource is a dict; extract product as the "source" approximation
                if isinstance(val, dict):
                    val = val.get("product") or val.get("category") or str(val)
                loki_labels[preferred] = str(val) if val else None
            else:
                loki_labels[preferred] = None  # runtime-populated

        # Apply label generation policy guards
        if not self._policy.get("include_severity", True):
            loki_labels.pop("priority", None)
        if not self._policy.get("include_source", True):
            loki_labels.pop("source", None)
        if not self._policy.get("include_rule_name", True):
            loki_labels.pop("rule", None)

        rule["_loki_labels"] = loki_labels
        return rule


class NormalizationEngine:
    """
    Orchestrates FieldNormalizer → LabelNormalizer in sequence.
    Entry point: normalize(rule: dict) → dict
    """

    def __init__(self, config: Config) -> None:
        self._field_normalizer = FieldNormalizer(config)
        self._label_normalizer = LabelNormalizer(config)

    def normalize(self, rule: dict) -> dict:
        """
        Apply field normalization followed by label normalization.
        Returns an enriched rule dict ready for backend conversion.
        """
        rule = self._field_normalizer.apply_field_mapping(rule)
        rule = self._label_normalizer.apply_label_mapping(rule)
        log.debug(
            "Normalized rule '%s': loki_labels=%s, field_aliases=%s",
            rule.get("title", "?"),
            rule.get("_loki_labels", {}),
            rule.get("_field_aliases", {}),
        )
        return rule
