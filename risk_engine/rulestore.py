"""Versioned, hot-reloadable rule store.

规则与代码解耦：
- 规则文件是带版本号的 JSON（rules/rules.vX.Y.Z.json），改参数/开关不需要发版；
- ``rules/current.json`` 指向当前生效版本，``RuleStore`` 每次 ``load`` 都重新读盘，
  进程内可通过 ``reload()`` 热更新；
- 每次发布的规则文件按版本归档保留，历史告警可用对应版本规则复现。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional

VERSION_RE = re.compile(r"^rules\.v(\d+)\.(\d+)\.(\d+)\.json$")
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class RuleConfigError(ValueError):
    """Raised when a rule config file is missing required fields or malformed."""


def _version_key(version: str) -> tuple[int, int, int]:
    m = SEMVER_RE.match(version)
    if not m:
        raise RuleConfigError(f"非法语义版本号: {version!r}，应为 X.Y.Z")
    return tuple(int(g) for g in m.groups())  # type: ignore[return-value]


def fingerprint(config: Dict[str, Any]) -> str:
    """Stable short hash of a rule config, used as an audit fingerprint."""
    blob = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:12]


def validate_config(config: Dict[str, Any]) -> None:
    if not isinstance(config, dict):
        raise RuleConfigError("规则配置必须是 JSON 对象")
    if "version" not in config:
        raise RuleConfigError("规则配置缺少 version 字段")
    _version_key(str(config["version"]))
    rules = config.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RuleConfigError("规则配置 rules 必须是非空数组")
    seen: set[str] = set()
    for r in rules:
        if not isinstance(r, dict) or "rule" not in r:
            raise RuleConfigError(f"非法规则条目: {r!r}")
        name = r["rule"]
        if name in seen:
            raise RuleConfigError(f"规则 {name} 在同一版本中重复定义")
        seen.add(name)
        if not isinstance(r.get("params", {}), dict):
            raise RuleConfigError(f"规则 {name} 的 params 必须是对象")
        if "enabled" in r and not isinstance(r["enabled"], bool):
            raise RuleConfigError(f"规则 {name} 的 enabled 必须是布尔值")


class RuleStore:
    """Loads rule configs from a directory and supports hot reload.

    目录布局::

        rules/
          rules.v1.0.0.json      # 归档版本，永久保留
          rules.v1.1.0.json
          current.json           # 当前生效版本（完整配置或 {"active": "1.1.0"}）
    """

    def __init__(self, rules_dir: str, explicit_file: Optional[str] = None):
        self.rules_dir = rules_dir
        self.explicit_file = os.path.abspath(explicit_file) if explicit_file else None
        self._config: Optional[Dict[str, Any]] = None
        self._source_path: Optional[str] = None
        self._mtime: Optional[float] = None

    # ---- loading -------------------------------------------------------
    def _resolve_current_path(self) -> str:
        if self.explicit_file:
            if not os.path.exists(self.explicit_file):
                raise FileNotFoundError(f"指定的规则文件不存在: {self.explicit_file}")
            return self.explicit_file
        cur = os.path.join(self.rules_dir, "current.json")
        if not os.path.exists(cur):
            raise FileNotFoundError(f"缺少当前规则指针文件: {cur}")
        with open(cur, encoding="utf-8") as fh:
            pointer = json.load(fh)
        if isinstance(pointer, dict) and "active" in pointer:
            version = str(pointer["active"])
            path = os.path.join(self.rules_dir, f"rules.v{version}.json")
        else:
            # current.json 本身就是一份完整配置
            path = cur
        if not os.path.exists(path):
            raise FileNotFoundError(f"current.json 指向的规则文件不存在: {path}")
        return path

    def load(self) -> Dict[str, Any]:
        """Load (or reload) the active config from disk."""
        path = self._resolve_current_path()
        with open(path, encoding="utf-8") as fh:
            config = json.load(fh)
        validate_config(config)
        self._config = config
        self._source_path = path
        self._mtime = os.path.getmtime(path)
        return config

    def reload_if_changed(self) -> bool:
        """Hot reload entry point. Returns True when a newer file was picked up."""
        path = self._resolve_current_path()
        mtime = os.path.getmtime(path)
        if self._config is not None and path == self._source_path and mtime == self._mtime:
            return False
        self.load()
        return True

    def reload(self) -> Dict[str, Any]:
        return self.load()

    # ---- accessors -----------------------------------------------------
    @property
    def config(self) -> Dict[str, Any]:
        if self._config is None:
            return self.load()
        return self._config

    @property
    def version(self) -> str:
        return str(self.config["version"])

    @property
    def source_path(self) -> str:
        if self._source_path is None:
            self.load()
        assert self._source_path is not None
        return self._source_path

    def active_rules(self) -> List[Dict[str, Any]]:
        return [r for r in self.config["rules"] if r.get("enabled", True)]

    def params(self, rule_name: str) -> Dict[str, Any]:
        for r in self.config["rules"]:
            if r["rule"] == rule_name:
                return r.get("params", {})
        raise KeyError(f"规则 {rule_name} 不存在于规则版本 {self.version}")

    # ---- publishing / versioning --------------------------------------
    def publish(self, config: Dict[str, Any], make_current: bool = True) -> str:
        """归档一份新版本规则，并可选切换 current 指针。

        已有同版本文件时拒绝覆盖，保证历史版本不可变。
        """
        validate_config(config)
        version = str(config["version"])
        path = os.path.join(self.rules_dir, f"rules.v{version}.json")
        if os.path.exists(path):
            raise FileExistsError(f"规则版本 {version} 已归档，历史版本不可覆盖")
        os.makedirs(self.rules_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        if make_current:
            with open(os.path.join(self.rules_dir, "current.json"), "w", encoding="utf-8") as fh:
                json.dump({"active": version}, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
        self.load()
        return path

    def list_versions(self) -> List[str]:
        if not os.path.isdir(self.rules_dir):
            return []
        versions = []
        for name in os.listdir(self.rules_dir):
            m = VERSION_RE.match(name)
            if m:
                versions.append(".".join(m.groups()))
        return sorted(versions, key=_version_key)
