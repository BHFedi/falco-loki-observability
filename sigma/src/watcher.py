"""
watcher.py — Entry point.

Watches SIGMA_RULES_DIR for new and modified Sigma rule files using watchdog,
routing each through the RulePipeline. Also performs an initial sweep of
existing files at startup to handle rules present before the container starts.
"""

import logging
import os
import signal
import sys
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from config import Config
from pipeline import RulePipeline

# ── Logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sigma.watcher")


# ── Watchdog event handler ────────────────────────────────────────────────────

class SigmaRuleHandler(FileSystemEventHandler):
    def __init__(self, pipeline: RulePipeline) -> None:
        super().__init__()
        self._pipeline = pipeline

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._pipeline.process_file(Path(str(event.src_path)))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._pipeline.process_file(Path(str(event.src_path)))

    def on_moved(self, event: FileSystemEvent) -> None:
        # Handle atomic saves (editors write to .tmp then rename)
        if not event.is_directory:
            self._pipeline.process_file(Path(str(event.dest_path)))


# ── Startup sweep ─────────────────────────────────────────────────────────────

def initial_sweep(pipeline: RulePipeline, rules_dir: Path) -> None:
    """Process any rules already present in the rules directory at startup."""
    log.info("Running initial sweep of %s", rules_dir)

    # FIX: sorted() on a generator is fine, but combining two sorted() lists
    # with + is correct Python — keeping it explicit and deduped via a set
    # to avoid double-processing files matched by both globs (unlikely but safe).
    seen: set[Path] = set()
    candidates: list[Path] = []
    for path in sorted(rules_dir.rglob("*.yml")):
        if path not in seen:
            seen.add(path)
            candidates.append(path)
    for path in sorted(rules_dir.rglob("*.yaml")):
        if path not in seen:
            seen.add(path)
            candidates.append(path)

    attempted = 0
    succeeded = 0
    for path in candidates:
        attempted += 1
        if pipeline.process_file(path):
            succeeded += 1

    stats = pipeline.stats()
    log.info(
        "Initial sweep complete: %d/%d rules deployed successfully | state=%s",
        succeeded, attempted, stats,
    )


# ── Graceful shutdown ─────────────────────────────────────────────────────────

class _ShutdownFlag:
    def __init__(self):
        self.triggered = False

    def handle(self, *_):
        log.info("Shutdown signal received")
        self.triggered = True


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("Starting Sigma container")

    config = Config()
    config.ensure_dirs()

    try:
        config.load_mappings()
    except FileNotFoundError as exc:
        log.critical("Cannot start: %s", exc)
        sys.exit(1)

    log.info("Config: %r", config)

    pipeline = RulePipeline(config)

    # Startup sweep
    initial_sweep(pipeline, config.rules_dir)

    # Set up watchdog observer
    handler = SigmaRuleHandler(pipeline)
    observer = Observer()
    observer.schedule(handler, str(config.rules_dir), recursive=True)
    observer.start()

    log.info(
        "Watching %s (poll every %ds, format=%s)",
        config.rules_dir, config.poll_interval, config.output_format,
    )

    shutdown = _ShutdownFlag()
    signal.signal(signal.SIGTERM, shutdown.handle)
    signal.signal(signal.SIGINT, shutdown.handle)

    try:
        while not shutdown.triggered:
            if not observer.is_alive():
                log.error("Watchdog observer died, restarting")
                observer = Observer()
                observer.schedule(handler, str(config.rules_dir), recursive=True)
                observer.start()
            time.sleep(config.poll_interval)
    finally:
        log.info("Stopping observer")
        observer.stop()
        observer.join()
        pipeline.teardown()
        log.info("Sigma container stopped | final stats: %s", pipeline.stats())


if __name__ == "__main__":
    main()
