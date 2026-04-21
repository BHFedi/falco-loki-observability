"""
debug_ruler.py — one-shot script to print exactly what pySigma ruler produces
for the test rule, then print the payload we'd send to Loki.
Run inside the container: python /app/src/debug_ruler.py
"""
import sys, yaml, re
sys.path.insert(0, "/app/src")

RULE_YAML = """
title: Suspicious Sudo Usage
id: a1b2c3d4-0001-0002-0003-000000000001
status: test
description: Detects suspicious sudo command execution
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'sudo su'
      - 'sudo -i'
      - 'sudo bash'
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.TA0004
"""

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection

backend = LogQLBackend(add_line_filters=True, case_sensitive=False)
collection = SigmaCollection.from_yaml(RULE_YAML)

print("=" * 60)
print("OUTPUT FORMAT: default (plain LogQL)")
print("=" * 60)
out = backend.convert(collection, output_format="default")
print(repr(out))

print()
print("=" * 60)
print("OUTPUT FORMAT: ruler")
print("=" * 60)
out = backend.convert(collection, output_format="ruler")
print("TYPE:", type(out))
print("REPR:", repr(out))
print()
print("RAW (if string):")
if isinstance(out, str):
    print(out)
elif isinstance(out, list):
    for i, item in enumerate(out):
        print(f"  item[{i}] type={type(item)} repr={repr(item)}")
        if isinstance(item, str):
            print(item)

print()
print("=" * 60)
print("PARSED YAML STRUCTURE:")
print("=" * 60)
raw = out if isinstance(out, str) else "\n---\n".join(str(x) for x in out)
try:
    docs = list(yaml.safe_load_all(raw))
    for i, doc in enumerate(docs):
        print(f"doc[{i}]:", yaml.dump(doc, default_flow_style=False))
except Exception as e:
    print("YAML parse error:", e)
