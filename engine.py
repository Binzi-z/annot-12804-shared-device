"""风控引擎 CLI。

用法（兼容旧入口）::

    python engine.py data/events.jsonl alerts.json
    python engine.py data/events.jsonl alerts.json --rules rules/current.json

规则从版本化 JSON 加载并在每次运行时重新读盘：替换 rules/current.json 指针即完成
热更新，无需改代码发版；历史规则文件按版本归档，告警中带 rule_version 可回溯。
事件文件格式保持原样，本脚本只读取、不修改。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# 兼容 python -I（隔离模式不自动把脚本目录加入 sys.path）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from risk_engine.detectors import load_events, run_engine
from risk_engine.rulestore import RuleStore, fingerprint

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="多账号同设备盗用风控检测引擎")
    p.add_argument("src", nargs="?", default="data/events.jsonl", help="JSONL 事件文件")
    p.add_argument("out", nargs="?", default="alerts.json", help="告警输出 JSON")
    p.add_argument(
        "--rules",
        default=None,
        help="规则文件或规则目录（默认 rules/ 目录，按 current.json 指针取生效版本）",
    )
    return p


def load_store(rules_arg: str | None) -> RuleStore:
    if rules_arg and os.path.isfile(rules_arg):
        # 直接指定某一版本规则文件：脱离 current 指针机制，按文件 mtime 热更新
        path = os.path.abspath(rules_arg)
        store = RuleStore(os.path.dirname(path), explicit_file=path)
        store.load()
        return store
    return RuleStore(rules_arg or DEFAULT_RULES_DIR)


def main(argv: list[str] | None = None) -> int:
    # Windows 控制台默认 GBK，强制 UTF-8 输出避免中文乱码
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    store = load_store(args.rules)
    store.reload_if_changed()
    config = store.config

    events = load_events(args.src)
    alerts = run_engine(events, config)
    # 内部辅助字段不写入输出
    for a in alerts:
        a.pop("_start", None)
        a.pop("_end", None)
        a.pop("_accounts", None)

    payload = {
        "rule_version": config["version"],
        "rule_source": os.path.basename(store.source_path),
        "rule_fingerprint": fingerprint(config),
        "event_count": len(events),
        "alerts": alerts,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(
        f"规则版本 {config['version']}（{os.path.basename(store.source_path)}）："
        f"{len(alerts)} alerts -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
