"""What two recorded plans must agree on: the resources, their actions, reasons and forcing arguments.

python tests/real/shape.py A.json B.json
"""

import json
import sys


def shape(path):
    plan = json.load(open(path))
    return sorted(
        (
            r["address"],
            r["change"]["actions"],
            r.get("action_reason"),
            r["change"].get("replace_paths"),
        )
        for r in plan["resource_changes"]
    ), sorted(plan.get("output_changes", {}))


if __name__ == "__main__":
    a, b = shape(sys.argv[1]), shape(sys.argv[2])
    if a != b:
        print("the plans differ:", json.dumps(a, indent=1), json.dumps(b, indent=1), sep="\n")
        sys.exit(1)
    print(f"same shape: {len(a[0])} resources")
