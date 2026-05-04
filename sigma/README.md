# Sigma → Grafana Alerting Pipeline

Watches a directory of [Sigma](https://sigmahq.io/) rules, converts them to LogQL via pySigma, and deploys them as live alert rules into Grafana using the provisioning REST API.

```
rules/*.yml  →  validate  →  normalize  →  convert  →  deploy  →  Grafana Alerting
                                                            ↓
                                                       state.json (dedup)
```

---

## Directory structure

```
sigma/
├── Dockerfile
├── requirements.txt
├── config/
│   ├── field_mapping.json     # Sigma field → Loki/Falco field translations
│   └── label_mapping.json     # Sigma label → Loki stream label translations
├── rules/                     # Drop Sigma YAML rules here — watched in real time
│   ├── test_sudo_usage.yml
│   └── test_ssh_bruteforce.yml
├── failed/                    # Quarantine dir — invalid rules land here with a .error sidecar
└── src/
    ├── watcher.py             # Entry point — watchdog + initial sweep
    ├── pipeline.py            # Orchestrator: validate → normalize → convert → deploy
    ├── validator.py           # YAML integrity + pySigma parse check
    ├── normalizer.py          # Field and label normalization
    ├── converter.py           # pySigma LogQL backend wrapper
    ├── deployer.py            # Grafana REST API upsert
    ├── state.py               # SHA256-based dedup state (survives restarts)
    ├── config.py              # Runtime config from environment variables
    └── healthcheck.py         # Docker HEALTHCHECK probe
```

---

## How it works

### 1. Watcher (`watcher.py`)
Uses [watchdog](https://pypi.org/project/watchdog/) to monitor `rules/` recursively for created, modified, and renamed files. On startup it runs an initial sweep of all existing rules. Each file event is routed to the pipeline.

### 2. Pipeline (`pipeline.py`)
For each file event:
- Skips temp/editor artifacts (`.swp`, `.tmp`, `~`, etc.)
- Waits for the file to finish writing (size-stability check)
- Runs validate → normalize → convert → deploy in sequence
- Records outcome in state; marks failed rules so they are retried when the file changes

### 3. Validator (`validator.py`)
Two-phase check:
- **Phase 1** — YAML integrity: must parse, must be a mapping, must contain `title`, `logsource`, `detection` with a `condition`
- **Phase 2** — pySigma parse: `SigmaCollection.from_yaml()` to catch unsupported constructs early

Invalid rules are copied to `failed/` with a `.error` sidecar explaining the reason.

### 4. Normalizer (`normalizer.py`)
Two sub-components run in sequence:
- **FieldNormalizer** — translates Sigma detection field names to canonical Loki/Falco field names using `field_mapping.json` (e.g. `CommandLine` → `proc.cmdline`)
- **LabelNormalizer** — builds `_loki_labels` dict for stream selector context using `label_mapping.json`

### 5. Converter (`converter.py`)
Wraps the [pySigma Loki backend](https://github.com/SigmaHQ/pySigma-backend-loki). Produces:
- `grafana_yaml` — Grafana provisioning file format (parsed and reshaped by deployer)
- `logql` — plain LogQL string kept as a diagnostic artifact

Backend options (add_line_filters, case_sensitive, datasource UID, folder, interval, contact point) are passed from config with introspection-based forward/backward compatibility.

### 6. Deployer (`deployer.py`)
pySigma outputs the Grafana **provisioning file** format (`apiVersion: 1 / groups / rules`). This is not the same as the REST API schema. The deployer:
1. Parses the pySigma YAML string into rule dicts
2. Reshapes each rule into the `POST /api/v1/provisioning/alert-rules` JSON schema
3. **Upserts**: `POST` to create (201), automatically retries with `PUT /{uid}` on conflict (409)
4. Ensures the target folder exists before posting, creating it with a stable UID if needed

### 7. State (`state.py`)
Composite identity key: `filename :: rule-uid :: sha256(content)`. Persisted as JSON in the `sigma-state` Docker volume. A rule is only reprocessed if its content actually changed — container restarts are safe.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SIGMA_RULES_DIR` | `/app/rules` | Watched rules directory |
| `SIGMA_STATE_DIR` | `/app/state` | Dedup state persistence |
| `SIGMA_FAILED_DIR` | `/app/failed` | Quarantine for invalid rules |
| `SIGMA_POLL_INTERVAL` | `5` | Watcher heartbeat in seconds |
| `SIGMA_FAIL_ON_INVALID` | `true` | Stop pipeline on validation failure |
| `SIGMA_OUTPUT_FORMAT` | `grafana_alerting` | `ruler` / `grafana_alerting` / `both` |
| `SIGMA_ADD_LINE_FILTERS` | `true` | pySigma line filter optimization |
| `SIGMA_CASE_SENSITIVE` | `false` | Case-sensitive LogQL matching |
| `SIGMA_FIELD_MAP_FILE` | `/app/config/field_mapping.json` | Field translation map |
| `SIGMA_LABEL_MAP_FILE` | `/app/config/label_mapping.json` | Label translation map |
| `NORMALIZATION_PROFILE` | `falco_loki` | Normalization profile name |
| `GRAFANA_URL` | `http://grafana:3000` | Grafana base URL |
| `GRAFANA_DATASOURCE_UID` | `loki` | Loki datasource UID in Grafana |
| `GRAFANA_FOLDER` | `security` | Target alert folder name |
| `GRAFANA_ORG_ID` | `1` | Grafana organisation ID |
| `GRAFANA_INTERVAL` | `1m` | Rule group evaluation interval |
| `GRAFANA_CONTACT_POINT` | `default` | Notification contact point |
| `GRAFANA_API_KEY_FILE` | _(empty)_ | Path to service-account token file |
| `GRAFANA_USER` | `admin` | Basic auth fallback username |
| `GRAFANA_PASSWORD` | `admin` | Basic auth fallback password |
| `LOKI_URL` | `http://loki:3100` | Loki base URL (used if `SIGMA_OUTPUT_FORMAT=ruler`) |
| `LOKI_TENANT_ID` | `fake` | `X-Scope-OrgID` header value for Loki |

---

## Adding a rule

Drop any valid Sigma YAML file into `sigma/rules/`. The watcher picks it up within `SIGMA_POLL_INTERVAL` seconds. No restart needed.

Minimal valid rule:

```yaml
title: My Detection Rule
id: xxxxxxxx-0000-0000-0000-000000000001   # must be unique — used as Grafana rule UID
status: test
description: Detects something suspicious
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    proc_cmdline|contains:
      - 'suspicious_binary'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.ta0002
```

> **Important:** always set a unique `id` field. It is used as the Grafana alert rule UID, which enables idempotent updates — the same rule file can be modified and redeployed without creating duplicates.

---

## Updating a rule

Edit the file in `rules/`. The watcher detects the content change (SHA256 differs), re-converts, and calls `PUT /api/v1/provisioning/alert-rules/{uid}` to update the existing Grafana rule in place.

---

## Invalid rules

If a rule fails validation it is copied to `failed/` with a `.error` sidecar:

```
failed/
├── bad_rule.yml
└── bad_rule.error     # contains the failure reason
```

Fix the source file in `rules/` and the watcher will retry it automatically.

---

## Healthcheck

The container exposes a Docker `HEALTHCHECK` via `healthcheck.py` that verifies:
1. The rules directory is mounted and accessible
2. The mapping config files exist and are readable
3. The Loki endpoint is reachable (warning only — non-fatal during startup)

```bash
docker inspect --format='{{.State.Health.Status}}' sigma
```

---

## Debugging

```bash
# Live logs
docker logs -f sigma

# Check deployed rules in Grafana
curl -s http://localhost:3000/api/v1/provisioning/alert-rules | \
  python3 -c "import json,sys; [print(r['title'], '|', r['folderUID'], '|', r['uid']) for r in json.load(sys.stdin)]"

# Run the converter manually inside the container
docker exec sigma python3 /app/src/debug_convert.py

# Clear dedup state (forces all rules to redeploy on next restart)
docker exec sigma rm -f /app/state/processed_rules.json

# Inspect a quarantined rule
cat sigma/failed/my_rule.error
```

---

## Auth

The deployer supports two auth modes for Grafana, tried in priority order:

1. **Bearer token** — set `GRAFANA_API_KEY_FILE` to a file containing a Grafana service-account token
2. **Basic auth** — fallback using `GRAFANA_USER` / `GRAFANA_PASSWORD` (default `admin`/`admin`)

For production, create a Grafana service account with the **Editor** role, generate a token, write it to `secrets/grafana_sigma_api_key.txt`, and re-enable `GRAFANA_API_KEY_FILE` in `docker-compose.yml`.
