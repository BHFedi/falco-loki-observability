# `analyser` — AI-Powered Falco Alert Analysis Container

The `analyser` container is the intelligence core of the **SIB (SIEM-in-a-Box)** stack. It receives Falco security alerts from Loki (ingested via Falcosidekick), obfuscates sensitive fields before sending them to an LLM, enriches results with local threat-intel feeds, and pushes structured analysis back to Loki for display in Grafana dashboards.

```
Falco → Falcosidekick → Loki → analyser → Loki (enriched) → Grafana
                                    ↕
                              LLM (Gemini / OpenAI / Ollama / Anthropic)
                                    ↕
                          Threat Intel Feeds (local, offline)
                                    ↕
                        Fleet push → remote Falco IDS targets
```

---

## Directory Structure

```
analysis/
├── Dockerfile
├── analyzer.py          # Core analysis engine (Loki client, LLM providers, CLI)
├── api.py               # Flask REST API + web UI (port 5000)
├── config.yaml          # Provider and stack configuration
├── fleet_dispatcher.py  # Fan-out rule push to remote Falco targets
├── obfuscator.py        # Privacy-preserving data redaction
├── prompts.py           # LLM system prompt, user prompt template, MITRE fallback map
├── requirements.txt
├── threatintel/
│   ├── lookup-ip.sh              # CLI IP reputation lookup tool
│   ├── update-feeds.sh           # Download / refresh threat intel feeds
│   └── rules.d/
│       └── falco_threatintel_rules.yaml   # Auto-generated Falco rules from feeds
└── threatintel.py       # In-memory threat intel database and enrichment logic
```

---

## How It Works

### 1. Alert Ingestion

Falco detects suspicious syscalls and container activity. Falcosidekick forwards the JSON alert to Loki. The `analyser` queries Loki via `LogQL` to fetch recent alerts.

### 2. Obfuscation

Before any alert is sent to an external LLM, `obfuscator.py` replaces sensitive fields with consistent deterministic tokens:

| Data Type | Token Pattern |
|---|---|
| External IPs | `[IP-EXTERNAL-1]`, `[IP-EXTERNAL-2]`, … |
| Internal IPs | `[IP-INTERNAL-1]`, … |
| Hostnames | `[HOST-1]`, … |
| Usernames | `[USER-1]`, … |
| Container IDs | `[CONTAINER-1]`, … |
| K8s names | `[POD-1]`, `[NS-1]`, … |
| Secrets/tokens | `[REDACTED]` |

Three obfuscation levels are available: `minimal`, `standard` (default), and `paranoid`. The level is set via `OBFUSCATION_LEVEL` in `docker-compose.yml` or `config.yaml`.

### 3. LLM Analysis

The obfuscated alert is sent to the configured LLM provider with a detailed security analyst system prompt. The LLM returns structured JSON covering:

- **Attack vector** — what the attacker is likely attempting
- **MITRE ATT&CK mapping** — tactic, technique ID, sub-technique
- **Risk assessment** — severity (Critical / High / Medium / Low), confidence, impact
- **Investigation steps** — Loki queries and Prometheus metrics to check
- **Mitigations** — immediate, short-term, and long-term actions
- **False positive assessment** — likelihood and distinguishing factors
- **Detection engineering feedback** — Falco rule quality and improvement suggestions
- **Executive summary** — one paragraph suitable for a security report

If the LLM fails to return valid JSON, a safe fallback template is used and the result is flagged `ai_failed: true` so it still appears in dashboards without silently dropping events.

Analyses are cached on disk (default TTL: 24 h) keyed by a normalised SHA-256 hash of the alert output and rule name. Repeated identical alerts (same rule, same behaviour) are deduplicated and a `dedup_count` counter is incremented instead of re-running the LLM.

### 4. Threat Intelligence Enrichment

`threatintel.py` maintains an in-memory database loaded from local feed files. Every IP address extracted from an alert is checked against the database before and after LLM analysis. The result includes:

- Which feeds matched (Feodo Tracker, SSL Blacklist, Emerging Threats, Blocklist.de, Spamhaus DROP, CI Army, Tor exit nodes)
- Severity per match (CRITICAL / HIGH / MEDIUM / INFO)
- Whether the IP is a confirmed C2 server

Feeds are refreshed by running `update-feeds.sh` (see [Threat Intelligence](#threat-intelligence) below).

### 5. Fleet Dispatch

After threat-intel rules are updated, `fleet_dispatcher.py` pushes the generated `falco_threatintel_rules.yaml` to all registered remote Falco IDS targets in parallel. Each target is tried via `POST /push-rules` first, falling back to `POST /webhook` for targets that only support pull-sync.

---

## Configuration

### `config.yaml`

```yaml
analysis:
  enabled: true
  obfuscation_level: standard   # minimal | standard | paranoid
  provider: gemini              # overridden by LLM_PROVIDER env var at runtime

  gemini:
    api_key: ${GEMINI_API_KEY}
    model: ${GEMINI_MODEL:-gemini-3-flash-preview}

  # Other providers (uncomment to use):
  # ollama:
  #   url: ${OLLAMA_URL:-http://ollama:11434}
  #   model: ${OLLAMA_MODEL:-llama3.1:8b}
  # openai:
  #   api_key: ${OPENAI_API_KEY}
  #   model: gpt-4o-mini
  # anthropic:
  #   api_key: ${ANTHROPIC_API_KEY}
  #   model: claude-sonnet-4-20250514

storage:
  backend: ${STACK:-loki}

loki:
  url: ${LOKI_URL:-http://loki:3100}
```

The `LLM_PROVIDER` environment variable always takes precedence over `config.yaml` at runtime.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | Active provider: `gemini`, `openai`, `anthropic`, `ollama` |
| `GEMINI_MODEL` | `gemini-3-flash-preview` | Gemini model name |
| `GEMINI_API_KEY_FILE` | `/run/secrets/gemini_api_key` | Docker secret path for Gemini API key |
| `OBFUSCATION_LEVEL` | `minimal` | Alert obfuscation level |
| `LOKI_URL` | `http://loki:3100` | Loki endpoint |
| `STACK` | `loki` | Storage backend |
| `RULES_DIR` | `/app/threatintel/rules.d` | Falco rules output directory |
| `FALCO_TARGETS_FILE` | `/run/secrets/falco_targets` | One IDS target URL per line |
| `FALCO_TARGET_KEYS_FILE` | `/run/secrets/falco_target_keys` | Per-target API keys (same order) |
| `FALCO_TARGET_LABELS_FILE` | *(optional)* | Human-readable labels for targets |
| `FLEET_DISPATCH_TIMEOUT` | `10` | Per-target HTTP timeout in seconds |
| `ANALYSIS_CACHE_TTL` | `86400` | Analysis cache TTL in seconds (24 h) |
| `THREATFOX_API_KEY_FILE` | `/run/secrets/threatfox_api_key` | ThreatFox API key (optional enrichment) |

### Secrets

All secrets are managed via Docker secret files mounted at `/run/secrets/`. The `_FILE` pattern is used throughout — the code reads the file path from `*_FILE` env vars first, then falls back to the bare env var.

| Secret file | Purpose |
|---|---|
| `secrets/gemini_api_key.txt` | Gemini API key |
| `secrets/falco_targets.txt` | Remote Falco/IDS target URLs (one per line) |
| `secrets/falco_target_keys.txt` | API keys for each target (same order as targets) |
| `secrets/threatfox_api_key.txt` | ThreatFox API key |

---

## REST API

The Flask API listens on **port 5000**. All endpoints listed below are relative to `http://localhost:5000`.

### Web UI Pages

| Path | Description |
|---|---|
| `GET /` | API home — lists all endpoints |
| `GET /analyze?output=<alert>` | Analyse a single Falco alert (HTML result page) |
| `GET /history` | Browse cached analysis history |
| `GET /threatintel` | Threat intel dashboard with IP lookup form |
| `GET /threatintel?ip=1.2.3.4` | Inline IP lookup result on the dashboard |

### Analysis Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Analyse a Falco alert (JSON in, JSON out) |
| `GET` | `/api/history` | List cached analyses (JSON) |
| `GET` | `/api/cache/stats` | Cache statistics |
| `POST` | `/api/cache/clear` | Evict all cached analyses |

**`POST /api/analyze` request body:**
```json
{
  "alert": "<raw Falco alert output>",
  "rule": "Terminal shell in container",
  "priority": "Warning",
  "hostname": "worker-01",
  "store": true
}
```

### Threat Intelligence Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/threatintel/lookup?ip=1.2.3.4` | Look up one or more IPs (comma-separated) |
| `GET` | `/api/threatintel/stats` | Feed statistics (counts, last updated) |
| `POST` | `/api/threatintel/reload` | Hot-reload feeds from disk without restarting |

### Rules Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/rules/falco` | Serve the current `falco_threatintel_rules.yaml` (optional `X-API-Key` auth) |

### Fleet / IDS Push Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/fleet/status` | List registered targets and their auth status |
| `POST` | `/api/fleet/push` | Push current rules file to all targets |
| `POST` | `/api/fleet/trigger` | Send lightweight pull-sync webhook to all targets |

### Health Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Container health (used by Docker healthcheck) |
| `GET` | `/api/health/all` | Aggregate health across the full stack (Loki, Grafana, Prometheus, Falcosidekick) |

---

## Threat Intelligence

Feed management is handled by shell scripts in `threatintel/`.

### Update Feeds

```bash
# Run from host (docker exec)
docker exec analyser /app/threatintel/update-feeds.sh

# Hot-reload after update (no restart needed)
curl -sX POST http://localhost:5000/api/threatintel/reload
```

Feeds are updated automatically after `update-feeds.sh` finishes — it calls the reload endpoint internally. Feeds older than 25 hours are flagged as stale in both the web UI and CLI tool.

### IP Lookup (CLI)

```bash
# Single IP
docker exec analyser /app/threatintel/lookup-ip.sh 185.220.101.1

# Multiple IPs
docker exec analyser /app/threatintel/lookup-ip.sh 185.220.101.1 45.33.32.156

# Returns exit code 1 if any IP is malicious (useful in CI/CD gates)
```

### Bundled Feeds

| Feed | Severity | Category |
|---|---|---|
| Feodo Tracker | CRITICAL | Banking trojans / botnet C2 |
| SSL Blacklist | CRITICAL | Malware C2 via SSL certificates |
| Emerging Threats (compromised) | HIGH | Compromised hosts |
| CI Army | HIGH | Composite threat intelligence |
| Blocklist.de (all) | MEDIUM | All attack types |
| Blocklist.de (SSH) | MEDIUM | SSH brute-force |
| Spamhaus DROP | HIGH | CIDR-level blocklist |
| Tor Exit Nodes | INFO | Anonymization infrastructure |

---

## CLI Usage

`analyzer.py` can be run as a standalone script inside the container for batch analysis, debugging, or dry-runs.

```bash
# Analyse last 5 alerts (default)
docker exec analyser python /app/analyzer.py

# Analyse last 24 hours of Critical alerts, store results in Loki
docker exec analyser python /app/analyzer.py \
  --priority Critical --last 24h --limit 20 --store

# Dry-run: show obfuscated data without calling the LLM
docker exec analyser python /app/analyzer.py --dry-run --verbose

# Output raw JSON
docker exec analyser python /app/analyzer.py --json

# Override Loki URL
docker exec analyser python /app/analyzer.py --loki-url http://loki:3100
```

| Flag | Short | Description |
|---|---|---|
| `--config` | `-c` | Path to config file |
| `--priority` | `-p` | Filter: `Critical`, `Error`, `Warning`, `Notice` |
| `--last` | `-l` | Time range, e.g. `15m`, `1h`, `24h`, `7d` (default: `1h`) |
| `--limit` | `-n` | Max alerts to analyse (default: `5`) |
| `--dry-run` | `-d` | Show obfuscated alert without calling LLM |
| `--store` | `-s` | Push enriched result back to Loki |
| `--verbose` | `-v` | Show obfuscation token map |
| `--json` | `-j` | Emit raw JSON instead of formatted output |
| `--loki-url` | | Override `loki.url` from config |

---

## Grafana Integration

The analyser is designed to serve as a **data-link target** from Grafana alert panels. When you click an alert in a Grafana dashboard, you can configure the data link to open:

```
http://localhost:5000/analyze?output=${__value.raw}
```

This renders a full HTML analysis page for that specific alert, including the MITRE mapping, mitigations, false-positive assessment, threat-intel enrichment, and the obfuscated payload that was sent to the LLM.

Analysis results pushed back to Loki (via `--store` or `store: true` in the API) carry the label `source="falco_analysis"` and can be queried in Grafana with:

```logql
{source="falco_analysis"} | json
```

---

## Adding a New LLM Provider

1. Create a new class in `analyzer.py` that inherits from `LLMProvider` and implements `analyze(system_prompt, user_prompt) -> dict`.
2. Register it in the `_create_provider()` factory method inside `AlertAnalyzer`.
3. Add the provider's config block to `config.yaml`.
4. Set `LLM_PROVIDER=<your_provider>` in `docker-compose.yml`.

---

## Volumes

| Volume | Mount path | Purpose |
|---|---|---|
| `analysis-cache` | `/app/cache` | Persisted analysis cache (survives restarts) |
| *(bind mount)* | `/app/config.yaml` | Live config file (read-only) |
| *(bind mount)* | `/app/threatintel/rules.d` | Generated Falco rules (read-write) |
