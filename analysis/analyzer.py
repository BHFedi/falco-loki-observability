"""
Alert Analyzer - LLM-powered security alert analysis

Fetches alerts from Loki (ingested via Falcosidekick), obfuscates sensitive data, 
and uses various LLM providers to provide attack vector analysis.
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

def read_secret(env_var: str) -> Optional[str]:
    """Read a secret from env var or Docker secret file."""
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path:
        try:
            with open(file_path, 'r') as f:
                return f.read().strip()
        except OSError:
            pass
    return os.environ.get(env_var)

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
            response = self.session.get(f"{self.url}/loki/api/v1/query_range", params=params, timeout=30)
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

class LLMProvider:
    """Base class for LLM providers."""
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        raise NotImplementedError

class OllamaProvider(LLMProvider):
    def __init__(self, url: str, model: str):
        self.url = url.rstrip('/')
        self.model = model
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
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
        content = response.json().get('message', {}).get('content', '{}')
        return json.loads(content)

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
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
        return json.loads(content)

class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
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
                "messages": [{"role": "user", "content": user_prompt}]
            },
            timeout=60
        )
        response.raise_for_status()
        content = response.json()['content'][0]['text']
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match: return json.loads(match.group())
            raise

class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str, model: str):
        self.model_name = model
        self.client = genai.Client(api_key=api_key)

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=f"{system_prompt}\n\n{user_prompt}",
                config=types.GenerateContentConfig(response_mime_type="application/json")
            )
            return json.loads(response.text)
        except Exception as e:
            return {"error": str(e), "success": False}

class AlertAnalyzer:
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
        analysis_config = self.config.get('analysis', {})
        provider_name = (
            os.getenv("LLM_PROVIDER") 
            or analysis_config.get('provider') 
            or 'ollama'
        )
        
        if provider_name == 'ollama':
            ollama_config = analysis_config.get('ollama', {})
            url = os.getenv("OLLAMA_URL") or ollama_config.get('url') or "http://ollama:11434"
            model = os.getenv("OLLAMA_MODEL") or ollama_config.get('model') or "llama3.1:8b"
            return OllamaProvider(url=url, model=model)

        elif provider_name == 'openai':
            openai_config = analysis_config.get('openai', {})
            api_key = read_secret("OPENAI_API_KEY") or openai_config.get('api_key')
            model = os.getenv("OPENAI_MODEL") or openai_config.get('model') or "gpt-4o-mini"
            return OpenAIProvider(api_key=api_key, model=model)

        elif provider_name == 'anthropic':
            anthropic_config = analysis_config.get('anthropic', {})
            api_key = read_secret("ANTHROPIC_API_KEY") or anthropic_config.get('api_key')
            model = os.getenv("ANTHROPIC_MODEL") or anthropic_config.get('model') or "claude-3-5-sonnet-20240620"
            return AnthropicProvider(api_key=api_key, model=model)

        elif provider_name == 'gemini':
            gemini_config = analysis_config.get('gemini', {})
            api_key = read_secret("GEMINI_API_KEY") or gemini_config.get('api_key')
            model = os.getenv("GEMINI_MODEL") or gemini_config.get('model') or "gemini-1.5-flash-latest"
            return GeminiProvider(api_key=api_key, model=model)
        
        raise ValueError(f"Unknown provider: {provider_name}")

    def fetch_alerts(self, priority: Optional[str] = None, last: str = "1h", limit: int = 10) -> List[dict]:
        duration_map = {'m': 'minutes', 'h': 'hours', 'd': 'days'}
        unit = last[-1]
        delta = timedelta(**{duration_map[unit]: int(last[:-1])})
        end = datetime.now()
        start = end - delta
        
        # LogQL optimization: Add limit inside the query for Loki efficiency
        query_base = '{source=~"syscall|k8s_audit"}'
        if priority:
            query_base = f'{{source=~"syscall|k8s_audit", priority="{priority}"}}'
        
        query = f'{query_base} | limit {limit}'
        return self.log_client.query_range(query, start, end, limit)

    def analyze_alert(self, alert: dict, dry_run: bool = False) -> dict:
        obfuscated, mapping = obfuscate_alert(alert, self.obfuscation_level)
        labels = alert.get('_labels', {})
        output_fields = obfuscated.get('output_fields', {})
        
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
        
        if dry_run:
            return {'obfuscated_prompt': user_prompt, 'obfuscation_mapping': mapping}

        rule_name = labels.get('rule', alert.get('rule', ''))
        quick_mitre = MITRE_MAPPING.get(rule_name, None)
        
        try:
            analysis = self.provider.analyze(SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            analysis = {'error': str(e), 'fallback_mitre': quick_mitre}
        
        return {'original_alert': alert, 'obfuscated_alert': obfuscated, 'obfuscation_mapping': mapping, 'analysis': analysis}

    def store_analysis(self, result: dict) -> bool:
        analysis = result.get('analysis', {})
        original = result.get('original_alert', {})
        labels = original.get('_labels', {})
        mitre = analysis.get('mitre_attack', {})
        risk = analysis.get('risk', {})
        
        enriched_labels = {
            'source': 'analysis',
            'type': 'enriched',
            'original_rule': labels.get('rule', 'unknown'),
            'original_priority': labels.get('priority', 'unknown'),
            'hostname': labels.get('hostname', 'unknown'),
            'severity': str(risk.get('severity', 'unknown')).lower(),
            'mitre_tactic': mitre.get('tactic', 'unknown').replace(' ', '_'),
            'mitre_technique': mitre.get('technique_id', 'unknown'),
        }
        
        return self.log_client.push(enriched_labels, json.dumps(analysis), original.get('_timestamp'))

    def analyze_batch(self, alerts: List[dict], dry_run: bool = False, store: bool = False) -> List[dict]:
        results = []
        for i, alert in enumerate(alerts):
            print(f"Analyzing alert {i+1}/{len(alerts)}...", file=sys.stderr)
            result = self.analyze_alert(alert, dry_run)
            results.append(result)
            if store and not dry_run and 'error' not in result.get('analysis', {}):
                self.store_analysis(result)
        return results

_SECRET_VARS = {'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'GRAFANA_ADMIN_PASSWORD'}

def expand_env_vars(obj):
    if isinstance(obj, dict):
        return {k: expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        def replace_var(match):
            var_name = match.group(1)
            default = match.group(3) if match.group(3) else ''
            if var_name in _SECRET_VARS:
                val = read_secret(var_name)
                return val if val is not None else default
            return os.environ.get(var_name, default)
        return re.sub(r'\$\{([^}:]+)(:-([^}]*))?\}', replace_var, obj)
    return obj

def load_config(config_path: Optional[str] = None) -> dict:
    config_path = config_path or os.getenv("CONFIG_PATH") or "/app/config.yaml"
    if os.path.exists(config_path):
        with open(config_path) as f:
            return expand_env_vars(yaml.safe_load(f))
    return {'analysis': {'provider': 'ollama'}, 'loki': {'url': 'http://loki:3100'}}

def print_analysis(result: dict, verbose: bool = False):
    analysis = result.get('analysis', {})
    if 'error' in analysis:
        print(f"\n❌ Error: {analysis['error']}")
        return
    print(f"\n🎯 Attack Vector: {analysis.get('attack_vector', 'N/A')}")
    print(f"📝 Summary: {analysis.get('summary', 'N/A')}")

def main():
    parser = argparse.ArgumentParser(description='Alert Analyzer')
    parser.add_argument('--config', '-c')
    parser.add_argument('--priority', '-p')
    parser.add_argument('--last', '-l', default='1h')
    parser.add_argument('--limit', '-n', type=int, default=5)
    parser.add_argument('--dry-run', '-d', action='store_true')
    parser.add_argument('--store', '-s', action='store_true')
    parser.add_argument('--json', '-j', action='store_true')
    args = parser.parse_args()

    config = load_config(args.config)
    analyzer = AlertAnalyzer(config)
    alerts = analyzer.fetch_alerts(priority=args.priority, last=args.last, limit=args.limit)
    
    if not alerts:
        print("No alerts found.")
        return

    results = analyzer.analyze_batch(alerts, dry_run=args.dry_run, store=args.store)
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        for r in results: print_analysis(r)

if __name__ == '__main__':
    main()
