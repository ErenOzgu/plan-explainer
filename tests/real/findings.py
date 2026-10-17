"""Reads `plan-explainer explain -f json` on standard input and prints one 'rule address' line per finding."""

import json
import sys

print("\n".join(sorted(f"{f['rule']} {f['address']}" for f in json.load(sys.stdin)["findings"])))
