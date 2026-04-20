"""
state.py — Idempotency and deduplication state manager.

Composite identity = filename + rule UID + SHA256(content).
State is persisted as a JSON file in SIGMA_STATE_DIR so the container
survives restarts without reprocessing unchanged rules.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_STATE_FILE_NAME = "processed_rules.json"


class StateManager:
    """
    Tracks which rules have been processed using a composite identity key.
    Thread-safe for single-threaded use (watcher runs serially per file event).
    """

    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir
        self._state_file = state_dir / _STATE_FILE_NAME
        self._state: dict[str, dict] = {}
        self._load()

    # ── Persistence ────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._state_file.exists():
            try:
                with open(self._state_file) as f:
                    self._state = json.load(f)
                log.info("Loaded state for %d rules from %s", len(self._state), self._state_file)
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not load state file (%s), starting fresh", exc)
                self._state = {}
        else:
            self._state = {}

    def _save(self) -> None:
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_file.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(self._state, f, indent=2)
            tmp.replace(self._state_file)
        except OSError as exc:
            log.error("Failed to persist state: %s", exc)

    # ── Identity helpers ───────────────────────────────────────────────────

    @staticmethod
    def file_hash(path: Path) -> str:
        """SHA256 of file content."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _identity_key(filename: str, rule_uid: str, content_hash: str) -> str:
        """Composite key: filename::uid::sha256"""
        return f"{filename}::{rule_uid}::{content_hash}"

    # ── Public API ─────────────────────────────────────────────────────────

    def is_seen(self, path: Path, rule: dict) -> bool:
        """
        Return True if this exact (filename, UID, content) combination
        has already been successfully processed.
        """
        filename = path.name
        uid = str(rule.get("id", ""))
        content_hash = self.file_hash(path)
        key = self._identity_key(filename, uid, content_hash)
        return key in self._state

    def mark_done(self, path: Path, rule: dict, outcomes: dict) -> None:
        """Record a successfully processed rule."""
        filename = path.name
        uid = str(rule.get("id", ""))
        content_hash = self.file_hash(path)
        key = self._identity_key(filename, uid, content_hash)
        self._state[key] = {
            "title": rule.get("title", filename),
            "uid": uid,
            "hash": content_hash,
            "file": filename,
            "outcomes": outcomes,
        }
        self._save()

    def mark_failed(self, path: Path, reason: str) -> None:
        """Record a failed rule (by filename only, content unknown or invalid)."""
        filename = path.name
        # Use a failure-specific key so it's retried if content changes
        key = f"FAILED::{filename}"
        self._state[key] = {
            "file": filename,
            "error": reason,
            "failed": True,
        }
        self._save()

    def remove_failed(self, path: Path) -> None:
        """Remove the failed marker for a file (e.g. when it's been corrected)."""
        key = f"FAILED::{path.name}"
        if key in self._state:
            del self._state[key]
            self._save()

    def stats(self) -> dict:
        total = len(self._state)
        failed = sum(1 for v in self._state.values() if v.get("failed"))
        return {"total": total, "failed": failed, "ok": total - failed}
