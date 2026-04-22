"""
pipeline.py — Rule processing pipeline.

Orchestrates for each detected file:
  validate → normalize → convert → deploy

Also guards against:
  - Partially-written files (size stability check)
  - Temporary editor artifacts
  - Recursive processing loops (output written to watched dir)
  - Duplicate/unchanged rules (via StateManager)
"""

import logging
import time
from pathlib import Path

from config import Config
from converter import RuleConverter
from deployer import RuleDeployer
from normalizer import NormalizationEngine
from state import StateManager
from validator import RuleValidator, ValidationError

log = logging.getLogger(__name__)

# Editor temp-file patterns to ignore
_IGNORE_PATTERNS = {".swp", ".swx", ".tmp", "~", ".bak", ".orig"}

# How long (seconds) to wait after a file stabilises before processing
_STABILITY_WAIT = 1.0
_STABILITY_CHECKS = 3


def _is_temp_artifact(path: Path) -> bool:
    name = path.name
    suffix = path.suffix
    return (
        suffix in _IGNORE_PATTERNS
        or name.startswith(".")
        or name.endswith("~")
        or name.startswith("#")
    )


def _is_sigma_file(path: Path) -> bool:
    return path.suffix in (".yml", ".yaml") and not _is_temp_artifact(path)


def _wait_for_stable(path: Path) -> bool:
    """
    Return True once the file size stops changing.
    Prevents processing partially-written files.
    """
    prev_size = -1
    for _ in range(_STABILITY_CHECKS):
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        if size == prev_size and size > 0:
            return True
        prev_size = size
        time.sleep(_STABILITY_WAIT)
    return prev_size > 0


class RulePipeline:
    """
    Single-entry-point processor for Sigma rule files.
    Instantiated once; process_file() called per file event.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._validator = RuleValidator(config.failed_dir, config.fail_on_invalid)
        self._engine = NormalizationEngine(config)
        self._converter = RuleConverter(config)
        self._deployer = RuleDeployer(config)
        self._state = StateManager(config.state_dir)

        # Resolve the output paths that should NOT be treated as input
        # to prevent recursive processing if rules/ and outputs overlap.
        self._watch_dir = config.rules_dir.resolve()

    def process_file(self, path: Path) -> bool:
        """
        Full pipeline for a single file.
        Returns True on successful deployment, False on skip or failure.
        """
        path = path.resolve()

        if not _is_sigma_file(path):
            log.debug("Skipping non-Sigma / temp file: %s", path.name)
            return False

        if not path.exists():
            log.debug("File gone before processing: %s", path.name)
            return False

        # Guard: prevent recursive loop if outputs land in the watched dir
        if self._is_output_artifact(path):
            log.debug("Skipping output artifact: %s", path.name)
            return False

        # Wait for the file to finish being written
        if not _wait_for_stable(path):
            log.warning("File unstable or empty, skipping: %s", path.name)
            return False

        # ── Validate ────────────────────────────────────────────────────
        try:
            rule = self._validator.validate(path)
        except ValidationError as exc:
            log.error("Validation failed: %s", exc)
            self._state.mark_failed(path, str(exc))
            return False

        # ── Idempotency check ────────────────────────────────────────────
        if self._state.is_seen(path, rule):
            log.info("Rule unchanged, skipping: %s", path.name)
            return False

        # Remove any stale failure marker for this file
        self._state.remove_failed(path)

        # ── Normalize ────────────────────────────────────────────────────
        try:
            normalized = self._engine.normalize(rule)
        except Exception as exc:
            log.error("Normalization error for '%s': %s", path.name, exc)
            self._state.mark_failed(path, f"normalization: {exc}")
            return False

        # ── Convert ──────────────────────────────────────────────────────
        try:
            result = self._converter.convert(normalized)
        except ValueError as exc:
            log.error("Conversion error for '%s': %s", path.name, exc)
            self._state.mark_failed(path, f"conversion: {exc}")
            return False

        if not result.has_output():
            log.warning("No output produced for '%s' — skipping deploy", path.name)
            return False

        # ── Deploy ───────────────────────────────────────────────────────
        try:
            outcomes = self._deployer.deploy(normalized, result)
        except Exception as exc:
            log.error("Deployment error for '%s': %s", path.name, exc)
            self._state.mark_failed(path, f"deployment: {exc}")
            return False

        any_success = any(outcomes.values())

        # FIX: Only mark done if at least one deployment target succeeded.
        # Previously, a 401/failed deploy was still recorded as "ok", causing
        # the rule to never be retried on the next watcher poll.
        if any_success:
            self._state.mark_done(path, rule, outcomes)
        else:
            reason = "all deployment targets failed: " + str(outcomes)
            log.warning("Deployment failed for '%s': %s", path.name, reason)
            self._state.mark_failed(path, reason)

        log.info(
            "Pipeline complete for '%s': outcomes=%s success=%s",
            rule.get("title", path.name),
            outcomes,
            any_success,
        )
        return any_success

    def _is_output_artifact(self, path: Path) -> bool:
        """
        Prevent recursive loops: if the converter outputs to the same watched
        directory, identify and skip those files.
        """
        name = path.name
        return name.startswith("converted_") or name.endswith("_converted.yaml")

    def stats(self) -> dict:
        return self._state.stats()

    def teardown(self) -> None:
        self._deployer.close()
