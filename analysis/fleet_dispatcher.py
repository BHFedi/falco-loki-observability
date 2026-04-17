#!/usr/bin/env python3
"""
fleet_dispatcher.py – Fan-out Falco rules to multiple IDS/sync-server targets.

Drop this file into the same directory as api.py.

Configuration:
  - FALCO_TARGETS_FILE (preferred, one URL per line)
  - FALCO_TARGETS (env var, comma-separated)
  - FALCO_TARGET_KEYS_FILE / FALCO_TARGET_KEYS (one key per target)
  - FALCO_TARGET_LABELS_FILE (optional)

Dispatch behaviour:
  - Primary:   POST to /push-rules with full YAML content
  - Fallback:  If /push-rules returns 404, POST to /webhook (trigger pull-sync)
"""

import logging
import os
import threading
from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

import requests

logger = logging.getLogger("fleet-dispatcher")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class FalcoTarget:
    url: str
    api_key: str = ""
    label: str = ""

    def __post_init__(self):
        self.url = self.url.rstrip("/")
        if not self.label:
            self.label = self.url


@dataclass
class DispatchResult:
    target: FalcoTarget
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    skipped: bool = False


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
def _read_file_lines(path: str) -> List[str]:
    """Read non-empty, non-comment lines from a file."""
    p = Path(path)
    if not p.exists():
        return []
    return [
        line.strip()
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_targets() -> List[FalcoTarget]:
    """Load targets from secret file (preferred) and/or environment variable."""
    urls: List[str] = []

    # Load from file first (Docker secret style)
    targets_file = os.environ.get("FALCO_TARGETS_FILE", "/run/secrets/falco_targets")
    if os.path.exists(targets_file):
        urls = _read_file_lines(targets_file)
        logger.info("Loaded %d target(s) from %s", len(urls), targets_file)

    # Merge additional targets from env var
    env_targets = os.environ.get("FALCO_TARGETS", "")
    if env_targets:
        env_urls = [u.strip() for u in env_targets.split(",") if u.strip()]
        existing = set(urls)
        for u in env_urls:
            if u not in existing:
                urls.append(u)
        logger.info("After merging FALCO_TARGETS env var: %d target(s)", len(urls))

    if not urls:
        return []

    # Load keys
    keys: List[str] = []
    keys_file = os.environ.get("FALCO_TARGET_KEYS_FILE", "/run/secrets/falco_target_keys")
    if os.path.exists(keys_file):
        keys = _read_file_lines(keys_file)
    elif os.environ.get("FALCO_TARGET_KEYS"):
        keys = [k.strip() for k in os.environ["FALCO_TARGET_KEYS"].split(",")]

    # Load labels (optional)
    labels: List[str] = []
    labels_file = os.environ.get("FALCO_TARGET_LABELS_FILE", "")
    if labels_file and os.path.exists(labels_file):
        labels = _read_file_lines(labels_file)

    # Assemble targets
    targets = []
    for i, url in enumerate(urls):
        key = keys[i] if i < len(keys) else ""
        label = labels[i] if i < len(labels) else f"target-{i+1:02d}"
        targets.append(FalcoTarget(url=url, api_key=key, label=label))

    return targets


# ---------------------------------------------------------------------------
# Main Dispatcher
# ---------------------------------------------------------------------------
class FleetDispatcher:
    """Manages pushing rules to multiple rules-sync / Falco targets."""

    PUSH_PATH = "/push-rules"
    WEBHOOK_PATH = "/webhook"
    TIMEOUT = int(os.environ.get("FLEET_DISPATCH_TIMEOUT", 12))

    def __init__(self, targets: Optional[List[FalcoTarget]] = None):
        self._targets = targets if targets is not None else load_targets()
        if self._targets:
            logger.info("FleetDispatcher initialized with %d target(s): %s",
                        len(self._targets), [t.label for t in self._targets])
        else:
            logger.info("FleetDispatcher: no targets configured — push disabled")

    def dispatch(self, rules_content: str) -> List[DispatchResult]:
        """Push full rules YAML to all targets (preferred method)."""
        if not self._targets:
            return []

        results: List[Optional[DispatchResult]] = [None] * len(self._targets)
        threads = []

        for idx, target in enumerate(self._targets):
            t = threading.Thread(
                target=self._push_to_target,
                args=(target, rules_content, results, idx),
                daemon=True,
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.TIMEOUT + 3)

        final_results = [r for r in results if r is not None]
        self._log_summary(final_results)
        return final_results

    def trigger_sync(self) -> List[DispatchResult]:
        """Send lightweight webhook trigger to all targets."""
        if not self._targets:
            return []

        results: List[Optional[DispatchResult]] = [None] * len(self._targets)
        threads = []

        for idx, target in enumerate(self._targets):
            t = threading.Thread(
                target=self._trigger_target,
                args=(target, results, idx),
                daemon=True,
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.TIMEOUT + 3)

        final_results = [r for r in results if r is not None]
        self._log_summary(final_results)
        return final_results

    def status(self) -> List[dict]:
        """Return status for /api/fleet/status endpoint."""
        return [
            {"label": t.label, "url": t.url, "auth": bool(t.api_key)}
            for t in self._targets
        ]

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------
    def _headers(self, target: FalcoTarget) -> dict:
        h = {"Content-Type": "application/yaml"}
        if target.api_key:
            h["X-API-Key"] = target.api_key
        return h

    def _push_to_target(self, target: FalcoTarget, rules_content: str,
                        results: List[Optional[DispatchResult]], idx: int):
        """Try /push-rules first, fallback to /webhook on 404."""
        try:
            resp = requests.post(
                f"{target.url}{self.PUSH_PATH}",
                data=rules_content.encode("utf-8"),
                headers=self._headers(target),
                timeout=self.TIMEOUT,
            )

            if resp.status_code in (200, 204):
                results[idx] = DispatchResult(target=target, success=True, status_code=resp.status_code)
                logger.info("[%s] Rules pushed successfully (%d)", target.label, resp.status_code)
                return

            if resp.status_code == 304:
                results[idx] = DispatchResult(target=target, success=True, status_code=304, skipped=True)
                logger.debug("[%s] Rules unchanged (304)", target.label)
                return

            if resp.status_code == 404:
                logger.debug("[%s] /push-rules not found → falling back to webhook", target.label)
                self._trigger_target(target, results, idx)
                return

            # Other error
            results[idx] = DispatchResult(
                target=target,
                success=False,
                status_code=resp.status_code,
                error=f"HTTP {resp.status_code}: {resp.text[:150]}"
            )
            logger.warning("[%s] Push failed: HTTP %s", target.label, resp.status_code)

        except requests.Timeout:
            results[idx] = DispatchResult(target=target, success=False, error=f"Timeout after {self.TIMEOUT}s")
            logger.warning("[%s] Push timed out", target.label)
        except Exception as exc:
            results[idx] = DispatchResult(target=target, success=False, error=str(exc))
            logger.error("[%s] Push error: %s", target.label, exc)

    def _trigger_target(self, target: FalcoTarget,
                        results: List[Optional[DispatchResult]], idx: int):
        """Send lightweight trigger to /webhook."""
        try:
            resp = requests.post(
                f"{target.url}{self.WEBHOOK_PATH}",
                headers={"Content-Type": "application/json", **({"X-API-Key": target.api_key} if target.api_key else {})},
                timeout=self.TIMEOUT,
            )

            if resp.status_code in (200, 204):
                results[idx] = DispatchResult(target=target, success=True, status_code=resp.status_code)
                logger.info("[%s] Webhook trigger OK", target.label)
            else:
                results[idx] = DispatchResult(
                    target=target, success=False, status_code=resp.status_code,
                    error=f"HTTP {resp.status_code}"
                )
                logger.warning("[%s] Webhook failed: %s", target.label, resp.status_code)

        except requests.Timeout:
            results[idx] = DispatchResult(target=target, success=False, error=f"Timeout after {self.TIMEOUT}s")
            logger.warning("[%s] Webhook timed out", target.label)
        except Exception as exc:
            results[idx] = DispatchResult(target=target, success=False, error=str(exc))
            logger.error("[%s] Webhook error: %s", target.label, exc)

    def _log_summary(self, results: List[DispatchResult]):
        ok = sum(1 for r in results if r.success and not r.skipped)
        skipped = sum(1 for r in results if r.skipped)
        failed = sum(1 for r in results if not r.success)
        logger.info(
            "Fleet dispatch summary: %d OK, %d unchanged, %d failed / %d total",
            ok, skipped, failed, len(results)
        )
