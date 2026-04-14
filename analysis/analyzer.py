"""
Alert Analyzer - LLM-powered security alert analysis

Fetches alerts from Loki (ingested via Falcosidekick), obfuscates sensitive data, 
and uses local Ollama LLM to provide attack vector analysis and mitigation strategies.
"""

import json
import os
import re
import sys
import argparse
import requests
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path
from google import genai
from google.genai import types

import yaml

from obfuscator import obfuscate_alert, ObfuscationLevel
from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE, MITRE_MAPPING
from threatintel import enrich_alert_with_threatintel


# ---------------------------------------------------------------------------
# Secret / env helpers
# ---------------------------------------------------------------------------

def read_secret(env_var: str) -> Optional[str]:
    """Read a secret from env var or Docker secret file (_FILE pattern)."""
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path:
        try:
            with open(file_path, 'r') as f:
                return f.read().strip()
        except OSError:
            pass
    return os.environ.get(env_var)


_SECRET_VARS = {'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'OLLAMA_API_KEY', 'GRAFANA_ADMIN_PASSWORD'}


def expand_env_vars(obj):
    """Recursively expand environment variables in config values."""
    if isinstance(obj, dict):
        return {k: expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        def replace_var(match):
            var_name = match.group(1)
            default = match.group(3) if match.group(3) else ''
            if var_name in _SECRET_VARS:
                value = read_secret(var_name)
                return value if value is not None else default
            return os.environ.get(var_name, default)
        return re.sub(r'\$\{([^}:]+)(:-([^}]*))?\}', replace_var, obj)
    return obj


# ---------------------------------------------------------------------------
# Loki client
# ---------------------------------------------------------------------------

class LokiClient:
    """Client for querying Falco alerts from Loki."""

    def __init__(self, url: str):
        if not url:
            raise ValueError("Loki URL must be provided")
        self.url = url.rstrip('/')
        self.session = requests.Session()

    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> List[dict]:
        """Query Loki for Falco alerts in a time range."""
        params = {
            'query': query,
            'start': int(start.timestamp() * 1e9),
            'end': int(end.timestamp() * 1e9),
            'limit': limit,
        }

        try:
            response = self.session.get(
                f"{self.url}/loki/api/v1/query_range", params=params, timeout=30
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error querying Loki: {e}", file=sys.stderr)
            return []

        data = response.json()
        alerts = []

        for stream in data.get('data', {}).get('result', []):
            labels = stream.get('stream', {})
            for value in stream.get('values', []):
                timestamp_ns, log_line = value
                try:
                    alert = json.loads(log_line)
                except json.JSONDecodeError:
                    alert = {'output': log_line}

                alert['_labels'] = labels
                alert['_timestamp'] = datetime.fromtimestamp(int(timestamp_ns) / 1e9)
                alerts.append(alert)

        return alerts

    def push(self, labels: Dict[str, str], log_line: str, timestamp: Optional[datetime] = None) -> bool:
        """Push enriched analysis result back to Loki."""
        if timestamp is None:
            timestamp = datetime.now()

        ts_ns = str(int(timestamp.timestamp() * 1e9))

        payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [[ts_ns, log_line]]
                }
            ]
        }

        try:
            response = self.session.post(
                f"{self.url}/loki/api/v1/push",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Failed to push to Loki: {e}", file=sys.stderr)
            return False


# ---------------------------------------------------------------------------
# LLM providers
# ---------------------------------------------------------------------------

class LLMProvider:
    """Base class for LLM providers."""

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        raise NotImplementedError


def safe_json_parse(text: str) -> dict:
    """
    Robustly parse a JSON response from an LLM.

    Handles:
    - Empty / None responses
    - Markdown-wrapped JSON (```json ... ```)
    - Extra text before/after the JSON object
    - Partial or truncated JSON (returns error dict)
    """
    if not text or not text.strip():
        print("PARSE ERROR: empty response from LLM", file=sys.stderr)
        return {"error": "empty_response", "raw": ""}

    # Strip markdown code fences if present
    stripped = re.sub(r'^```(?:json)?\s*', '', text.strip(), flags=re.IGNORECASE)
    stripped = re.sub(r'\s*```$', '', stripped.strip())

    # Try direct parse first (fastest path)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Fall back to extracting the first {...} block
    match = re.search(r'\{.*\}', stripped, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError as e:
            print(f"PARSE ERROR: JSON decode failed after extraction: {e}", file=sys.stderr)
            return {"error": "invalid_json", "raw": text[:500]}

    print(f"PARSE ERROR: no JSON object found in response. Raw (first 500 chars): {text[:500]}", file=sys.stderr)
    return {"error": "no_json_found", "raw": text[:500]}


# Sentinel dict used to fill in safe defaults when the LLM analysis fails,
# so downstream code never silently shows empty "N/A" fields.
FAILED_ANALYSIS_TEMPLATE = {
    "attack_vector": "AI_ANALYSIS_FAILED — unable to determine attack vector.",
    "mitre_attack": {
        "tactic": "Unknown",
        "technique_id": "Unknown",
        "technique_name": "Analysis unavailable",
        "sub_technique": None,
    },
    "risk": {
        "severity": "Unknown",
        "confidence": "Low",
        "impact": "AI analysis failed; manual review required.",
    },
    "investigate": ["Manual triage required — AI analysis was unavailable for this alert."],
    "mitigations": {
        "immediate": ["Manually review the alert and apply standard incident-response procedures."],
        "short_term": [],
        "long_term": [],
    },
    "false_positive": {
        "likelihood": "Unknown",
        "common_causes": [],
        "distinguishing_factors": [],
    },
    "detection_feedback": {
        "rule_quality": "Unknown",
        "improvement_suggestions": [],
    },
    "summary": "AI analysis failed for this alert. Manual triage is required.",
}


def make_failed_analysis(error_msg: str, raw: str = "") -> dict:
    """Return a fully-populated analysis dict that signals AI failure rather than empty N/A fields."""
    result = FAILED_ANALYSIS_TEMPLATE.copy()
    result = json.loads(json.dumps(result))  # deep copy via JSON
    result["error"] = error_msg
    result["summary"] = f"AI analysis failed: {error_msg}. Manual triage is required."
    if raw:
        result["_raw_response"] = raw[:500]
    return result


class OllamaProvider(LLMProvider):
    """Local Ollama LLM provider - recommended for privacy."""

    def __init__(self, url: str = "http://ollama:11434", model: str = "llama3.1:8b"):
        self.url = url.rstrip('/')
        self.model = model

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            response = requests.post(
                f"{self.url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "stream": False,
                    "format": "json"
                },
                timeout=120
            )
            response.raise_for_status()
            content = response.json().get('message', {}).get('content', '')
            parsed = safe_json_parse(content)
            if "error" in parsed:
                return make_failed_analysis(parsed["error"], parsed.get("raw", ""))
            return parsed
        except Exception as e:
            print(f"OllamaProvider error: {e}", file=sys.stderr)
            return make_failed_analysis(str(e))


class OpenAIProvider(LLMProvider):
    """OpenAI API provider - requires API key."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        if not api_key:
            raise ValueError("OpenAI API key is missing")
        self.api_key = api_key
        self.model = model

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "response_format": {"type": "json_object"}
                },
                timeout=60
            )
            response.raise_for_status()
            content = response.json()['choices'][0]['message']['content']
            parsed = safe_json_parse(content)
            if "error" in parsed:
                return make_failed_analysis(parsed["error"], parsed.get("raw", ""))
            return parsed
        except Exception as e:
            print(f"OpenAIProvider error: {e}", file=sys.stderr)
            return make_failed_analysis(str(e))


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider - requires API key."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        if not api_key:
            raise ValueError("Anthropic API key is missing")
        self.api_key = api_key
        self.model = model

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": 4096,
                    "system": system_prompt,
                    "messages": [
                        {"role": "user", "content": user_prompt}
                    ]
                },
                timeout=60
            )
            response.raise_for_status()
            content = response.json()['content'][0]['text']
            parsed = safe_json_parse(content)
            if "error" in parsed:
                return make_failed_analysis(parsed["error"], parsed.get("raw", ""))
            return parsed
        except Exception as e:
            print(f"AnthropicProvider error: {e}", file=sys.stderr)
            return make_failed_analysis(str(e))


class GeminiProvider(LLMProvider):
    """Google Gemini API provider using the modern GenAI SDK."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        # Validate API key eagerly so the error is obvious at startup,
        # not silently swallowed during the first analysis call.
        if not api_key:
            raise ValueError("Gemini API key is missing — set GEMINI_API_KEY or gemini.api_key in config")
        self.model_name = model
        self.client = genai.Client(api_key=api_key)

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Call Gemini and return a parsed analysis dict.

        Robust error handling covers:
        - Network / API failures  → make_failed_analysis()
        - Empty response text     → make_failed_analysis()
        - Markdown-wrapped JSON   → safe_json_parse() strips fences
        - Partial / invalid JSON  → safe_json_parse() extracts best-effort object
        """
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=f"{system_prompt}\n\n{user_prompt}",
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                )
            )

            raw_text = response.text if response.text else ""
            print(f"[GeminiProvider] raw response (first 300 chars): {raw_text[:300]}", file=sys.stderr)

            parsed = safe_json_parse(raw_text)

            if "error" in parsed:
                print(f"[GeminiProvider] parse failed: {parsed['error']}", file=sys.stderr)
                return make_failed_analysis(parsed["error"], parsed.get("raw", raw_text))

            return parsed

        except Exception as e:
            print(f"[GeminiProvider] API error: {e}", file=sys.stderr)
            return make_failed_analysis(str(e))


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class AlertAnalyzer:
    """Main analyzer class for Falco alerts."""

    def __init__(self, config: dict):
        self.config = config
        self.loki_url = (
            os.getenv("LOKI_URL")
            or config.get('loki', {}).get('url')
            or "http://loki:3100"
        )
        self.log_client = LokiClient(self.loki_url)
        self.obfuscation_level = config.get('analysis', {}).get('obfuscation_level', 'standard')
        self.provider = self._create_provider()

    def _create_provider(self) -> LLMProvider:
        """Create the configured LLM provider (default: ollama)."""
        analysis_config = self.config.get('analysis', {})

        provider_name = (
            os.getenv("LLM_PROVIDER")
            or analysis_config.get('provider')
            or 'ollama'
        )

        if provider_name == 'ollama':
            ollama_config = analysis_config.get('ollama', {})
            url = (
                os.getenv("OLLAMA_URL")
                or ollama_config.get('url')
                or "http://ollama:11434"
            )
            model = (
                os.getenv("OLLAMA_MODEL")
                or ollama_config.get('model')
                or "llama3.1:8b"
            )
            return OllamaProvider(url=url, model=model)

        elif provider_name == 'openai':
            openai_config = analysis_config.get('openai', {})
            api_key = (
                openai_config.get('api_key')
                or read_secret("OPENAI_API_KEY")
                or ""
            )
            return OpenAIProvider(
                api_key=api_key,
                model=openai_config.get('model', 'gpt-4o-mini')
            )

        elif provider_name == 'anthropic':
            anthropic_config = analysis_config.get('anthropic', {})
            api_key = (
                anthropic_config.get('api_key')
                or read_secret("ANTHROPIC_API_KEY")
                or ""
            )
            return AnthropicProvider(
                api_key=api_key,
                model=anthropic_config.get('model', 'claude-sonnet-4-20250514')
            )

        elif provider_name == 'gemini':
            gemini_config = analysis_config.get('gemini', {})
            api_key = (
                gemini_config.get('api_key')
                or read_secret("GEMINI_API_KEY")
                or ""
            )
            return GeminiProvider(
                api_key=api_key,
                model=gemini_config.get('model', 'gemini-2.0-flash')
            )

        else:
            raise ValueError(f"Unknown provider: {provider_name}")

    def fetch_alerts(self, priority: Optional[str] = None,
                     last: str = "1h", limit: int = 10) -> List[dict]:
        """Fetch Falco alerts from Loki."""
        duration_map = {'m': 'minutes', 'h': 'hours', 'd': 'days'}
        unit = last[-1]
        if unit not in duration_map:
            raise ValueError(f"Invalid time unit '{unit}'. Use 'm' (minutes), 'h' (hours), or 'd' (days).")
        value = int(last[:-1])
        delta = timedelta(**{duration_map[unit]: value})

        end = datetime.now()
        start = end - delta

        if priority:
            query = f'{{source=~"syscall|k8s_audit", priority="{priority}"}} | limit {limit}'
        else:
            query = f'{{source=~"syscall|k8s_audit"}} | limit {limit}'

        return self.log_client.query_range(query, start, end, limit)

    def analyze_alert(self, alert: dict, dry_run: bool = False) -> dict:
        """Analyze a single Falco alert, enriched with threat intelligence."""
        # ── 1. Obfuscate the alert for LLM privacy ──────────────────────────
        #       Must happen FIRST so we have the ip→token mapping before
        #       building the threat intel LLM context.
        obfuscated, mapping = obfuscate_alert(alert, self.obfuscation_level)

        # ── 2. Threat intel enrichment on the RAW alert ──────────────────────
        #       extract_ips_from_alert() reads the original alert so real IPs
        #       are looked up even under STANDARD/PARANOID obfuscation levels.
        #       We pass `mapping` so context_for_llm uses tokens ([IP-EXTERNAL-1])
        #       instead of real IPs — the LLM never sees raw addresses.
        ti = enrich_alert_with_threatintel(alert, obfuscation_map=mapping)
        ti_data = ti["threat_intel"]

        labels = alert.get('_labels', {})
        output_fields = obfuscated.get('output_fields', {})

        # ── 3. Build the LLM prompt ──────────────────────────────────────────
        user_prompt = USER_PROMPT_TEMPLATE.format(
            rule_name=labels.get('rule', alert.get('rule', 'Unknown')),
            priority=labels.get('priority', alert.get('priority', 'Unknown')),
            timestamp=alert.get('_timestamp', 'Unknown'),
            source=labels.get('source', 'syscall'),
            obfuscated_output=obfuscated.get('output', str(obfuscated)),
            container_image=output_fields.get('container.image.repository', 'N/A'),
            container_name=output_fields.get('container.name', 'N/A'),
            k8s_namespace=output_fields.get('k8s.ns.name', 'N/A'),
            k8s_pod_name=output_fields.get('k8s.pod.name', 'N/A'),
            syscall=output_fields.get('syscall.type', 'N/A'),
            process=output_fields.get('proc.name', 'N/A'),
            pid=output_fields.get('proc.pid', 'N/A'),
            parent_process=output_fields.get('proc.pname', 'N/A'),
            ppid=output_fields.get('proc.ppid', 'N/A'),
            user=output_fields.get('user.name', 'N/A'),
            uid=output_fields.get('user.uid', 'N/A'),
            terminal=output_fields.get('proc.tty', 'N/A'),
        )

        # Append threat intel context so the LLM knows about confirmed C2 hits
        user_prompt += f"\n\n**{ti_data['context_for_llm']}**"

        if dry_run:
            return {
                'obfuscated_prompt': user_prompt,
                'obfuscation_mapping': mapping,
                'threat_intel': ti_data,
                'note': 'Dry run - no LLM call made'
            }

        # ── 4. Bump severity hint when C2 is confirmed ──────────────────────
        rule_name = labels.get('rule', alert.get('rule', ''))
        quick_mitre = MITRE_MAPPING.get(rule_name, None)

        # ── 5. Call LLM ──────────────────────────────────────────────────────
        try:
            analysis = self.provider.analyze(SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            print(f"Unexpected provider error: {e}", file=sys.stderr)
            analysis = make_failed_analysis(str(e))

        # If analysis failed, enrich with any static MITRE fallback we have.
        if analysis.get("error") and quick_mitre:
            analysis.setdefault("mitre_attack", {}).update(quick_mitre)
            analysis["_fallback_mitre"] = True

        # ── 6. Escalate severity when threat intel confirms C2 ───────────────
        if ti_data["has_c2"] and not analysis.get("error"):
            risk = analysis.setdefault("risk", {})
            current = risk.get("severity", "Medium")
            # Only escalate, never downgrade
            rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
            if rank.get(current, 0) < rank["Critical"]:
                risk["severity"] = "Critical"
                risk["_ti_escalated"] = True

        return {
            'original_alert': alert,
            'obfuscated_alert': obfuscated,
            'obfuscation_mapping': mapping,
            'threat_intel': ti_data,
            'analysis': analysis
        }

    def store_analysis(self, result: dict) -> bool:
        """Store analysis result in Loki for Grafana dashboards."""
        analysis = result.get('analysis', {})
        original = result.get('original_alert', {})
        labels = original.get('_labels', {})
        ti = result.get('threat_intel', {})

        mitre = analysis.get('mitre_attack', {})
        risk = analysis.get('risk', {})
        fp = analysis.get('false_positive', {})

        enriched_labels = {
            'source': 'analysis',
            'type': 'enriched',
            'original_rule': labels.get('rule', 'unknown'),
            'original_priority': labels.get('priority', 'unknown'),
            'hostname': labels.get('hostname', 'unknown'),
            'severity': risk.get('severity', 'unknown').lower(),
            'mitre_tactic': mitre.get('tactic', 'unknown').replace(' ', '_'),
            'mitre_technique': mitre.get('technique_id', 'unknown'),
            'false_positive_likelihood': str(fp.get('likelihood', 'unknown')).lower(),
            # Threat intel labels — filterable in Grafana
            'ti_has_threats': str(ti.get('has_threats', False)).lower(),
            'ti_has_c2': str(ti.get('has_c2', False)).lower(),
            'ti_severity': ti.get('highest_severity', 'CLEAN').lower(),
        }

        enriched_entry = {
            'timestamp': original.get('_timestamp', datetime.now()).isoformat()
                if isinstance(original.get('_timestamp'), datetime)
                else str(original.get('_timestamp', '')),
            'original_output': original.get('output', ''),
            'rule': labels.get('rule', ''),
            'priority': labels.get('priority', ''),
            'hostname': labels.get('hostname', ''),
            'attack_vector': analysis.get('attack_vector', ''),
            'mitre_attack': mitre,
            'risk': risk,
            'mitigations': analysis.get('mitigations', {}),
            'false_positive': analysis.get('false_positive', {}),
            'summary': analysis.get('summary', ''),
            'investigate': analysis.get('investigate', []),
            'ai_failed': bool(analysis.get('error')),
            'threat_intel': {
                'checked_ips': ti.get('checked_ips', []),
                'malicious_ips': ti.get('malicious_ips', []),
                'has_threats': ti.get('has_threats', False),
                'has_c2': ti.get('has_c2', False),
                'highest_severity': ti.get('highest_severity', 'CLEAN'),
            },
            'prometheus_correlation': {
                'node_cpu_usage': f'rate(node_cpu_seconds_total{{instance=~"{labels.get("hostname", ".*")}:9100"}}[5m])',
                'container_memory': f'container_memory_usage_bytes{{pod=~"{labels.get("k8s_pod_name", ".*")}"}}',
            }
        }

        return self.log_client.push(
            enriched_labels,
            json.dumps(enriched_entry),
            original.get('_timestamp')
        )

    def analyze_batch(self, alerts: List[dict], dry_run: bool = False, store: bool = False) -> List[dict]:
        """Analyze multiple Falco alerts."""
        results = []
        for i, alert in enumerate(alerts):
            print(f"Analyzing alert {i+1}/{len(alerts)}...", file=sys.stderr)
            result = self.analyze_alert(alert, dry_run)
            results.append(result)

            # Store regardless of AI failure (failed analyses are still worth keeping
            # so the history page doesn't silently drop events).
            if store and not dry_run:
                if self.store_analysis(result):
                    status = "⚠️  AI failed, stored error record" if result['analysis'].get('error') else "✓ Stored analysis in Loki"
                    print(f"  {status}", file=sys.stderr)
                else:
                    print(f"  ✗ Failed to store analysis", file=sys.stderr)

        return results


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from file with environment variable expansion."""
    config = None

    config_path = config_path or os.getenv("CONFIG_PATH")

    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            config = yaml.safe_load(f)
    elif os.path.exists("/app/config.yaml"):
        with open("/app/config.yaml") as f:
            config = yaml.safe_load(f)
    elif os.path.exists("config.yaml"):
        with open("config.yaml") as f:
            config = yaml.safe_load(f)

    if config:
        return expand_env_vars(config)

    # Hard fallback
    return {
        'analysis': {
            'enabled': True,
            'obfuscation_level': 'standard',
            'provider': 'ollama',
            'ollama': {
                'url': os.getenv("OLLAMA_URL", "http://ollama:11434"),
                'model': 'llama3.1:8b'
            }
        },
        'loki': {
            'url': os.getenv("LOKI_URL", "http://loki:3100")
        }
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_analysis(result: dict, verbose: bool = False):
    """Pretty print analysis results."""
    analysis = result.get('analysis', {})

    if 'error' in analysis:
        print(f"\n❌ Analysis Error: {analysis['error']}")
        if analysis.get('_fallback_mitre'):
            print(f"   Fallback MITRE: {analysis.get('mitre_attack')}")
        if verbose and analysis.get('_raw_response'):
            print(f"   Raw response snippet: {analysis['_raw_response']}")
        # Still print whatever fields we have (the failed template is fully populated)

    print("\n" + "="*70)
    print("🔍 SECURITY ALERT ANALYSIS")
    if analysis.get('error'):
        print("⚠️  NOTE: AI analysis failed — fields below are defaults, not AI output")
    print("="*70)

    print(f"\n🎯 Attack Vector:")
    print(f"   {analysis.get('attack_vector', 'N/A')}")

    mitre = analysis.get('mitre_attack', {})
    print(f"\n📊 MITRE ATT&CK:")
    print(f"   Tactic: {mitre.get('tactic', 'N/A')}")
    print(f"   Technique: {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
    if mitre.get('sub_technique'):
        print(f"   Sub-technique: {mitre.get('sub_technique')}")

    risk = analysis.get('risk', {})
    severity_colors = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Unknown': '⚪'}
    print(f"\n⚠️  Risk Assessment:")
    print(f"   Severity: {severity_colors.get(risk.get('severity', ''), '⚪')} {risk.get('severity', 'N/A')}")
    print(f"   Confidence: {risk.get('confidence', 'N/A')}")
    print(f"   Impact: {risk.get('impact', 'N/A')}")

    mitigations = analysis.get('mitigations', {})
    print(f"\n🛡️  Mitigations:")
    if mitigations.get('immediate'):
        print("   Immediate:")
        for m in mitigations['immediate']:
            print(f"     • {m}")
    if mitigations.get('short_term'):
        print("   Short-term:")
        for m in mitigations['short_term']:
            print(f"     • {m}")
    if mitigations.get('long_term'):
        print("   Long-term:")
        for m in mitigations['long_term']:
            print(f"     • {m}")

    fp = analysis.get('false_positive', {})
    print(f"\n🤔 False Positive Assessment:")
    print(f"   Likelihood: {fp.get('likelihood', 'N/A')}")
    if fp.get('common_causes'):
        print("   Common legitimate causes:")
        for cause in fp['common_causes'][:3]:
            print(f"     • {cause}")

    print(f"\n📝 Summary:")
    print(f"   {analysis.get('summary', 'N/A')}")

    if verbose:
        print(f"\n🔐 Obfuscation Mapping:")
        print(json.dumps(result.get('obfuscation_mapping', {}), indent=2))

    print("\n" + "="*70)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='SIB Alert Analyzer - AI-powered Falco security alert analysis'
    )
    parser.add_argument('--config', '-c', help='Path to config file')
    parser.add_argument('--priority', '-p', choices=['Critical', 'Error', 'Warning', 'Notice'],
                        help='Filter by Falco priority')
    parser.add_argument('--last', '-l', default='1h',
                        help='Time range (e.g., 15m, 1h, 24h, 7d)')
    parser.add_argument('--limit', '-n', type=int, default=5,
                        help='Maximum number of alerts to analyze')
    parser.add_argument('--dry-run', '-d', action='store_true',
                        help='Show obfuscated data without calling LLM')
    parser.add_argument('--store', '-s', action='store_true',
                        help='Store analysis results in Loki for Grafana dashboards')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed output including obfuscation mapping')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output raw JSON instead of formatted text')
    parser.add_argument('--loki-url', help='Override Loki URL')

    args = parser.parse_args()

    config = load_config(args.config)

    if args.loki_url:
        config.setdefault('loki', {})['url'] = args.loki_url

    if not config.get('analysis', {}).get('enabled', True):
        print("Analysis is disabled in config. Set analysis.enabled: true to enable.")
        sys.exit(1)

    analyzer = AlertAnalyzer(config)

    print(f"Fetching Falco alerts from last {args.last}...", file=sys.stderr)
    alerts = analyzer.fetch_alerts(priority=args.priority, last=args.last, limit=args.limit)

    if not alerts:
        print("No Falco alerts found matching criteria.")
        sys.exit(0)

    print(f"Found {len(alerts)} alerts. Analyzing...", file=sys.stderr)

    results = analyzer.analyze_batch(alerts, dry_run=args.dry_run, store=args.store)

    if args.json:
        def json_serial(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        print(json.dumps(results, indent=2, default=json_serial))
    else:
        for result in results:
            print_analysis(result, verbose=args.verbose)


if __name__ == '__main__':
    main()
