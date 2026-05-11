"""
validator.py — Structural and schema validation for Sigma rules.

IMPROVED VERSION: Uses pySigma's SigmaValidator framework

Performs three-phase validation:
  1. YAML integrity — ensure the file is valid YAML with required Sigma fields
  2. pySigma parse — SigmaCollection.from_yaml() to catch parsing errors
  3. pySigma validation — comprehensive rule validation using SigmaValidator framework
     with checks for best practices, security issues, and rule quality

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
    Validates a Sigma rule file using a three-phase approach:
    
    Phase 1: YAML structure validation
    Phase 2: pySigma rule parsing
    Phase 3: pySigma comprehensive validation (best practices, security, quality)
    
    Returns the parsed rule dict on success; raises ValidationError on failure.
    """

    def __init__(self, failed_dir: Path, fail_on_invalid: bool = True) -> None:
        self._failed_dir = failed_dir
        self._fail_on_invalid = fail_on_invalid
        
        # Try to load pySigma validators at initialization
        self._pysigma_available = False
        self._pysigma_validators = None
        try:
            from sigma.validators.core import validators
            self._pysigma_validators = validators
            self._pysigma_available = True
            log.info("pySigma validators loaded: %d validators available", 
                    len(validators))
        except ImportError:
            log.warning("pySigma validators not available - will use basic parsing only")

    def validate(self, path: Path) -> dict:
        """
        Full validation pipeline for a single rule file.
        Returns the parsed rule dict.
        Raises ValidationError (and quarantines the file) on any failure.
        """
        # Phase 1: YAML integrity check
        raw = self._load_yaml(path)
        self._check_required_fields(raw, path)
        self._check_unsupported_constructs(raw, path)
        self._check_detection_block(raw, path)
        
        # Phase 2 & 3: pySigma parse and validation
        self._pysigma_parse_and_validate(path)
        
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

    # ── Phase 2 & 3: pySigma parse + comprehensive validation ─────────────

    def _pysigma_parse_and_validate(self, path: Path) -> None:
        """
        Perform pySigma parsing and comprehensive rule validation.
        
        This uses pySigma's SigmaValidator framework which performs checks for:
        - Rule structure and syntax (parsing)
        - Best practices (wildcard usage, modifiers, etc.)
        - Security issues (dangerous constructs)
        - Rule quality (metadata, tags, descriptions)
        - Cross-rule validation (uniqueness, references, etc.)
        
        High-severity issues are treated as validation failures.
        Medium/Low-severity issues are logged as warnings but don't block deployment.
        """
        try:
            from sigma.collection import SigmaCollection
            from sigma.validation import SigmaValidator
            
            with open(path) as f:
                raw_yaml = f.read()
            
            # Phase 2: Parse the rule file using pySigma
            # This catches syntax errors, unknown constructs, etc.
            try:
                collection = SigmaCollection.from_yaml(raw_yaml)
            except Exception as exc:
                msg = f"pySigma parse error: {exc}"
                self._quarantine(path, msg)
                raise ValidationError(f"{path.name}: {msg}") from exc
            
            # Phase 3: Run comprehensive validation if validators are available
            if self._pysigma_available and self._pysigma_validators:
                self._run_pysigma_validation(path, collection)
            else:
                log.debug("pySigma validators not available, skipping comprehensive validation")
                
        except ImportError:
            # pySigma not installed at all - graceful degradation
            log.debug("pySigma not available for validation - basic YAML checks only")
        except ValidationError:
            # Re-raise validation errors (already quarantined)
            raise
        except Exception as exc:
            msg = f"pySigma validation error: {exc}"
            self._quarantine(path, msg)
            raise ValidationError(f"{path.name}: {msg}") from exc

    def _run_pysigma_validation(self, path: Path, collection) -> None:
        """
        Run pySigma's comprehensive rule validation framework.
        
        Creates a SigmaValidator with all available validators and runs:
        - Individual rule checks (structure, best practices, security)
        - Cross-rule checks (uniqueness, references)
        - Finalization checks (aggregated issues)
        
        High-severity issues block deployment.
        Medium/Low-severity issues are logged as warnings.
        """
        try:
            from sigma.validation import SigmaValidator
            
            # Create validator with all available validators
            validator = SigmaValidator(self._pysigma_validators.values())
            
            # Run validation on all rules in the collection
            issues = validator.validate_rules(collection)
            
            if not issues:
                log.debug("pySigma validation passed with no issues")
                return
            
            # Separate issues by severity
            high_severity = []
            medium_severity = []
            low_severity = []
            
            for issue in issues:
                severity = issue.severity.name if hasattr(issue.severity, 'name') else str(issue.severity)
                
                if severity == "high":
                    high_severity.append(issue)
                elif severity == "medium":
                    medium_severity.append(issue)
                else:  # low
                    low_severity.append(issue)
            
            # Log all issues
            if high_severity:
                log.warning("High-severity validation issues for '%s':", path.name)
                for issue in high_severity:
                    log.warning("  - %s: %s", type(issue).__name__, issue.description)
            
            if medium_severity:
                log.info("Medium-severity validation issues for '%s':", path.name)
                for issue in medium_severity:
                    log.info("  - %s: %s", type(issue).__name__, issue.description)
            
            if low_severity:
                log.debug("Low-severity validation issues for '%s':", path.name)
                for issue in low_severity:
                    log.debug("  - %s: %s", type(issue).__name__, issue.description)
            
            # Block deployment only on high-severity issues
            if high_severity:
                issue_descs = [f"{type(issue).__name__}: {issue.description}" 
                              for issue in high_severity]
                msg = f"pySigma validation failures: {'; '.join(issue_descs)}"
                self._quarantine(path, msg)
                raise ValidationError(f"{path.name}: {msg}")
            
        except ValidationError:
            # Re-raise validation errors (already quarantined)
            raise
        except Exception as exc:
            log.error("Error running pySigma validators: %s", exc)
            # Don't fail on validator errors, only on validation failures
            pass

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
