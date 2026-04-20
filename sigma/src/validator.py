"""
validator.py — Structural and schema validation for Sigma rules.

Performs two-phase validation:
  1. YAML integrity — ensure the file is valid YAML with required Sigma fields
  2. pySigma parse — attempt to parse via SigmaCollection to catch unsupported
     constructs (complex correlations, deprecated syntax, etc.) early

Invalid rules are quarantined to SIGMA_FAILED_DIR rather than deleted.
"""

import logging
import shutil
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

# Required top-level Sigma fields
_REQUIRED_FIELDS = {"title", "logsource", "detection"}

# Constructs we explicitly reject before even trying the backend
_UNSUPPORTED_CONSTRUCTS = [
    "correlation",      # Sigma correlation rules — not yet fully supported
    "timeframe",        # Some uses of timeframe in legacy rules
]


class ValidationError(Exception):
    """Raised when a rule fails validation."""


class RuleValidator:
    """
    Validates a Sigma rule file.
    Returns the parsed rule dict on success; raises ValidationError on failure.
    """

    def __init__(self, failed_dir: Path, fail_on_invalid: bool = True) -> None:
        self._failed_dir = failed_dir
        self._fail_on_invalid = fail_on_invalid

    def validate(self, path: Path) -> dict:
        """
        Full validation pipeline for a single rule file.
        Returns the parsed rule dict.
        Raises ValidationError (and quarantines the file) on any failure.
        """
        raw = self._load_yaml(path)
        self._check_required_fields(raw, path)
        self._check_unsupported_constructs(raw, path)
        self._check_detection_block(raw, path)
        self._pysigma_parse_check(path)
        return raw

    # ── Phase 1: YAML integrity ───────────────────────────────────────────

    def _load_yaml(self, path: Path) -> dict:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                self._quarantine(path, "YAML does not parse to a mapping")
                raise ValidationError(f"{path.name}: not a YAML mapping")
            return data
        except yaml.YAMLError as exc:
            self._quarantine(path, f"YAML parse error: {exc}")
            raise ValidationError(f"{path.name}: YAML error: {exc}") from exc

    def _check_required_fields(self, rule: dict, path: Path) -> None:
        missing = _REQUIRED_FIELDS - set(rule.keys())
        if missing:
            msg = f"Missing required fields: {sorted(missing)}"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}")

    def _check_unsupported_constructs(self, rule: dict, path: Path) -> None:
        rule_type = rule.get("type", "")
        if rule_type in _UNSUPPORTED_CONSTRUCTS:
            msg = f"Unsupported rule type: '{rule_type}'"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}")

        # Also check for 'correlation' as a top-level key (some rule formats)
        if "correlation" in rule:
            msg = "Sigma correlation rules are not supported"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}")

    def _check_detection_block(self, rule: dict, path: Path) -> None:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            msg = "Detection block is not a mapping"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}")
        if "condition" not in detection:
            msg = "Detection block missing 'condition'"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}")

    # ── Phase 2: pySigma parse check ─────────────────────────────────────

    def _pysigma_parse_check(self, path: Path) -> None:
        """Attempt to parse the rule with SigmaCollection to catch backend errors early."""
        try:
            from sigma.collection import SigmaCollection
            with open(path) as f:
                raw_yaml = f.read()
            SigmaCollection.from_yaml(raw_yaml)
        except ImportError:
            log.debug("pySigma not available for pre-parse check — skipping")
        except Exception as exc:
            msg = f"pySigma parse error: {exc}"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}") from exc

    # ── Quarantine ─────────────────────────────────────────────────────────

    def _quarantine(self, path: Path, reason: str) -> None:
        """Move invalid rule to the failed/ directory and log the reason."""
        dest = self._failed_dir / path.name
        try:
            self._failed_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            # Write a sidecar error file
            with open(dest.with_suffix(".error"), "w") as f:
                f.write(reason + "\n")
            log.warning("Quarantined invalid rule: %s → %s (%s)", path.name, dest, reason)
        except OSError as exc:
            log.error("Failed to quarantine %s: %s", path.name, exc)
