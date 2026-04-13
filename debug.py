#!/usr/bin/env python3
"""
Ultimate SIEM Debugger - Checks all components end-to-end
Tests: Gemini API, Loki connectivity, secrets, analysis pipeline
"""

import os
import sys
import json
import requests
from datetime import datetime
from pathlib import Path

def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def print_status(name, status, details=""):
    icon = "✅" if status else "❌"
    print(f"{icon} {name:<30} {details}")

def check_gemini_api():
    """Test Gemini API connectivity and list available models."""
    print_header("GEMINI API CHECK")

    try:
        from google import genai
        from google.genai import types

        # Check for API key
        api_key = None
        if os.path.exists('/run/secrets/gemini_api_key'):
            with open('/run/secrets/gemini_api_key', 'r') as f:
                api_key = f.read().strip()
            print_status("Secret file exists", True, f"({len(api_key)} chars)")
        else:
            api_key = os.getenv('GEMINI_API_KEY')
            print_status("Env var GEMINI_API_KEY", api_key is not None, 
                        f"({len(api_key)} chars)" if api_key else "")

        if not api_key:
            print_status("API Key found", False, "No key in secrets or env!")
            return False

        # Try to initialize client
        client = genai.Client(api_key=api_key)
        print_status("Client initialized", True)

        # List available models
        print("\n📋 Available Models:")
        try:
            models = client.models.list()
            for model in models:
                if 'generateContent' in str(model.supported_actions):
                    print(f"   • {model.name}")
        except Exception as e:
            print(f"   ⚠️  Could not list models: {e}")

        # Test simple generation
        print("\n🧪 Testing generation...")
        model_name = os.getenv('GEMINI_MODEL', 'gemini-3-flash-preview')
        response = client.models.generate_content(
            model=model_name,
            contents="Say 'OK' if you can read this.",
            config=types.GenerateContentConfig(max_output_tokens=10)
        )
        print_status("Generation test", True, f"Response: {response.text[:50]}")
        return True

    except ImportError as e:
        print_status("Google GenAI SDK", False, str(e))
        return False
    except Exception as e:
        print_status("Gemini API", False, str(e))
        return False

def check_loki():
    """Test Loki connectivity and query capabilities."""
    print_header("LOKI CHECK")

    loki_url = os.getenv('LOKI_URL', 'http://loki:3100')
    print(f"Loki URL: {loki_url}")

    # Test 1: Ready endpoint
    try:
        r = requests.get(f"{loki_url}/ready", timeout=5)
        print_status("Loki /ready", r.status_code == 200, r.text[:50])
    except Exception as e:
        print_status("Loki /ready", False, str(e))
        return False

    # Test 2: Query Falco alerts
    try:
        query = '{source=~"syscall|k8s_audit"}'
        r = requests.get(
            f"{loki_url}/loki/api/v1/query_range",
            params={'query': query, 'limit': 1, 'since': '1h'},
            timeout=10
        )
        data = r.json()
        result_count = len(data.get('data', {}).get('result', []))
        print_status("Falco alerts query", result_count > 0, f"{result_count} streams found")
    except Exception as e:
        print_status("Falco alerts query", False, str(e))

    # Test 3: Query analysis results
    try:
        query = '{source="analysis"}'
        r = requests.get(
            f"{loki_url}/loki/api/v1/query_range",
            params={'query': query, 'limit': 1, 'since': '1h'},
            timeout=10
        )
        data = r.json()
        result_count = len(data.get('data', {}).get('result', []))
        print_status("Analysis results query", True, f"{result_count} streams found")

        # Show sample if exists
        if result_count > 0:
            sample = data['data']['result'][0]['values'][0][1]
            parsed = json.loads(sample)
            print(f"\n📄 Sample analysis: {parsed.get('rule', 'N/A')[:50]}")

    except Exception as e:
        print_status("Analysis results query", False, str(e))

    return True

def check_analyser_api():
    """Test the analyser API endpoints."""
    print_header("ANALYSER API CHECK")

    base_url = "http://localhost:5000"

    # Health check
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        print_status("/health", r.status_code == 200, r.json().get('status'))
    except Exception as e:
        print_status("/health", False, str(e))

    # Full stack health
    try:
        r = requests.get(f"{base_url}/api/health/all", timeout=5)
        data = r.json()
        print_status("Stack health", data.get('status') == 'healthy', 
                    f"({len(data.get('services', {}))} services)")
        for svc, info in data.get('services', {}).items():
            if isinstance(info, dict):
                print(f"   • {svc}: {info.get('status', 'unknown')}")
    except Exception as e:
        print_status("Stack health", False, str(e))

    # Test analysis (dry run, no storage)
    try:
        test_alert = {
            "alert": "Test alert for debugging",
            "rule": "DebugRule",
            "priority": "High",
            "hostname": "debug-host",
            "store": False
        }
        r = requests.post(f"{base_url}/api/analyze", 
                       json=test_alert, 
                       timeout=30)
        data = r.json()
        has_analysis = 'analysis' in data and 'error' not in data.get('analysis', {})
        print_status("Analysis endpoint", has_analysis)
        if has_analysis:
            analysis = data['analysis']
            print(f"   Severity: {analysis.get('risk', {}).get('severity', 'N/A')}")
            print(f"   Confidence: {analysis.get('risk', {}).get('confidence', 'N/A')}")
        else:
            print(f"   Error: {data.get('analysis', {}).get('error', 'Unknown')}")
    except Exception as e:
        print_status("Analysis endpoint", False, str(e))

    return True

def check_docker_setup():
    """Check Docker-specific configurations."""
    print_header("DOCKER SETUP CHECK")

    # Check secrets
    secrets_dir = Path('/run/secrets')
    if secrets_dir.exists():
        secrets = list(secrets_dir.iterdir())
        print_status("Secrets directory", True, f"{len(secrets)} secrets found")
        for secret in secrets:
            size = secret.stat().st_size
            print(f"   • {secret.name}: {size} bytes")
    else:
        print_status("Secrets directory", False, "/run/secrets not found")

    # Check environment
    print("\n📋 Key Environment Variables:")
    env_vars = ['LLM_PROVIDER', 'GEMINI_MODEL', 'LOKI_URL', 'STACK', 
                'GEMINI_API_KEY', 'GEMINI_API_KEY_FILE']
    for var in env_vars:
        val = os.getenv(var, 'NOT SET')
        masked = val[:20] + '...' if val and len(val) > 23 else val
        print(f"   {var:<25} = {masked}")

    # Check config file
    config_paths = ['/app/config.yaml', './config.yaml', '../config.yaml']
    for path in config_paths:
        if os.path.exists(path):
            print_status(f"Config file ({path})", True)
            try:
                import yaml
                with open(path) as f:
                    config = yaml.safe_load(f)
                provider = config.get('analysis', {}).get('provider', 'N/A')
                print(f"   Provider in config: {provider}")
            except Exception as e:
                print(f"   Error reading: {e}")
            break
    else:
        print_status("Config file", False, "Not found in standard locations")

    return True

def check_network():
    """Check network connectivity between services."""
    print_header("NETWORK CONNECTIVITY CHECK")

    services = [
        ('loki', 3100, '/ready'),
        ('falcosidekick', 2801, '/healthz'),
        ('grafana', 3000, '/api/health'),
        ('prometheus', 9090, '/-/ready'),
    ]

    for name, port, path in services:
        try:
            r = requests.get(f"http://{name}:{port}{path}", timeout=3)
            print_status(f"{name}:{port}", r.status_code < 400, f"HTTP {r.status_code}")
        except Exception as e:
            print_status(f"{name}:{port}", False, str(e)[:40])

    return True

def run_full_pipeline_test():
    """Run a complete end-to-end test."""
    print_header("FULL PIPELINE TEST")

    print("Testing: Alert → Analysis → Loki Storage\n")

    try:
        # Step 1: Send alert for analysis with storage
        test_alert = {
            "alert": "Read sensitive file untrusted: user=root command=cat /etc/shadow",
            "rule": "Read sensitive file untrusted",
            "priority": "Critical",
            "hostname": "pipeline-test",
            "store": True
        }

        print("1. Sending alert to analyser...")
        r = requests.post("http://localhost:5000/api/analyze", 
                         json=test_alert, 
                         timeout=30)
        data = r.json()

        if 'error' in data.get('analysis', {}):
            print_status("Analysis", False, data['analysis']['error'])
            return False

        print_status("Analysis completed", True)
        print(f"   Severity: {data['analysis'].get('risk', {}).get('severity')}")

        # Step 2: Verify it was stored in Loki
        print("\n2. Checking Loki for stored analysis...")
        import time
        time.sleep(2)  # Brief delay for Loki ingestion

        query = '{source="analysis",hostname="pipeline-test"}'
        r = requests.get(
            "http://localhost:3100/loki/api/v1/query_range",
            params={'query': query, 'limit': 1, 'since': '5m'},
            timeout=10
        )
        loki_data = r.json()
        results = loki_data.get('data', {}).get('result', [])

        if results:
            print_status("Stored in Loki", True, f"{len(results)} result(s)")
            # Parse and show summary
            log_line = results[0]['values'][0][1]
            parsed = json.loads(log_line)
            print(f"   Stored rule: {parsed.get('rule', 'N/A')}")
            print(f"   Stored severity: {parsed.get('risk', {}).get('severity', 'N/A')}")
            return True
        else:
            print_status("Stored in Loki", False, "No results found")
            return False

    except Exception as e:
        print_status("Pipeline test", False, str(e))
        return False

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║           SIEM ULTIMATE DEBUG TOOL                       ║
    ║   Checks: Gemini API | Loki | Analyser | Network         ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    results = {}

    # Run all checks
    results['docker'] = check_docker_setup()
    results['network'] = check_network()
    results['gemini'] = check_gemini_api()
    results['loki'] = check_loki()
    results['api'] = check_analyser_api()
    results['pipeline'] = run_full_pipeline_test()

    # Summary
    print_header("SUMMARY")
    all_passed = all(results.values())

    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        icon = "✅" if passed else "❌"
        print(f"{icon} {name.upper():<15} {status}")

    print(f"\n{'='*60}")
    if all_passed:
        print("🎉 ALL CHECKS PASSED - System is fully operational!")
    else:
        print("⚠️  SOME CHECKS FAILED - Review errors above")
    print(f"{'='*60}\n")

    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())

