"""
healthcheck.py — Docker HEALTHCHECK probe.

Verifies:
  1. The rules/ directory is accessible and mounted
  2. The mapping config files exist and are readable
  3. The Loki endpoint is reachable (if configured)

Exits 0 = healthy, 1 = unhealthy.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def check(condition: bool, msg: str) -> None:
    if not condition:
        print(f"UNHEALTHY: {msg}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    # 1. Rules dir
    rules_dir = Path(os.environ.get("SIGMA_RULES_DIR", "/app/rules"))
    check(rules_dir.exists(), f"Rules dir missing: {rules_dir}")

    # 2. Mapping files
    for env_key, label in (
        ("SIGMA_FIELD_MAP_FILE", "field_mapping"),
        ("SIGMA_LABEL_MAP_FILE", "label_mapping"),
    ):
        path = Path(os.environ.get(env_key, ""))
        if path and str(path) != ".":
            check(path.exists(), f"{label} file missing: {path}")

    # 3. Loki reachability (non-fatal warning only — Loki may not be up yet)
    loki_url = os.environ.get("LOKI_URL", "http://loki:3100")
    try:
        req = urllib.request.urlopen(f"{loki_url}/ready", timeout=3)
        if req.status not in (200, 204):
            print(f"WARNING: Loki not ready (HTTP {req.status})", file=sys.stderr)
    except Exception as exc:
        print(f"WARNING: Loki unreachable: {exc}", file=sys.stderr)
        # Don't fail health — Loki may be starting up

    print("OK")
    sys.exit(0)


if __name__ == "__main__":
    main()
