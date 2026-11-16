"""规则发布 / 热更新 / 回滚的命令行工具。

示例::

    # 归档并发布一个新版本（自动切换 current 指针，下次运行引擎即生效）
    python rules/rulectl.py publish rules/rules.v1.1.0.json

    # 只归档，不切换
    python rules/rulectl.py publish rules/rules.v1.1.0.json --no-activate

    # 回滚到历史版本（历史文件不可变，回滚只是移动指针）
    python rules/rulectl.py activate 1.0.0

    # 查看所有已归档版本与当前生效版本
    python rules/rulectl.py list
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk_engine.rulestore import RuleConfigError, RuleStore  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def cmd_list(store: RuleStore) -> int:
    current = None
    pointer = os.path.join(store.rules_dir, "current.json")
    if os.path.exists(pointer):
        with open(pointer, encoding="utf-8") as fh:
            current = json.load(fh).get("active")
    for v in store.list_versions():
        mark = "  (current)" if v == current else ""
        print(f"v{v}{mark}")
    if current and not any(v == current for v in store.list_versions()):
        print(f"v{current}  (current, 但归档文件缺失!)", file=sys.stderr)
        return 1
    return 0


def cmd_publish(store: RuleStore, path: str, activate: bool) -> int:
    with open(path, encoding="utf-8") as fh:
        config = json.load(fh)
    try:
        out = store.publish(config, make_current=activate)
    except (RuleConfigError, FileExistsError) as exc:
        print(f"发布失败: {exc}", file=sys.stderr)
        return 1
    print(f"已归档规则 v{config['version']} -> {out}")
    if activate:
        print(f"current 指针已切换，下次引擎运行即生效（热更新）")
    return 0


def cmd_activate(store: RuleStore, version: str) -> int:
    archived = store.list_versions()
    if version not in archived:
        print(f"版本 {version} 未归档，可选: {archived}", file=sys.stderr)
        return 1
    pointer = os.path.join(store.rules_dir, "current.json")
    with open(pointer, "w", encoding="utf-8") as fh:
        json.dump({"active": version}, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"current 已回滚/切换到 v{version}")
    return 0


def main() -> int:
    store = RuleStore(RULES_DIR)
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "list":
        return cmd_list(store)
    if cmd == "publish":
        if len(sys.argv) < 3:
            print("用法: rulectl.py publish <规则文件> [--no-activate]", file=sys.stderr)
            return 1
        return cmd_publish(store, sys.argv[2], "--no-activate" not in sys.argv[3:])
    if cmd == "activate":
        if len(sys.argv) < 3:
            print("用法: rulectl.py activate <版本号>", file=sys.stderr)
            return 1
        return cmd_activate(store, sys.argv[2])
    print(f"未知子命令: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
