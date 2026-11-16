"""Baseline: hardcoded amount threshold.

Every rule change needs a release. This is what the risk team runs today.
"""

from __future__ import annotations

import json
import sys

THRESHOLD = 10000


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "data/events.jsonl"
    out = sys.argv[2] if len(sys.argv) > 2 else "alerts.json"
    alerts = []
    with open(src, encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            e = json.loads(line)
            if e.get("amount", 0) >= THRESHOLD:
                alerts.append({"rule": "amount_gt_10000", "line": no, "account": e["account"], "amount": e["amount"]})
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"alerts": alerts}, fh, ensure_ascii=False, indent=2)
    print(f"{len(alerts)} alerts -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
