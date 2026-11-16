"""检测规则测试：真实数据全量回归 + 同设备多账号盗用/家庭共用合成样本。

合成事件严格沿用线上事件格式（ts/account/device/amount/action/ip_region），
只在测试内构造，不改动 data/events.jsonl。
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from risk_engine.detectors import (  # noqa: E402
    DETECTORS,
    load_events,
    run_engine,
)
from risk_engine.rulestore import RuleConfigError, RuleStore, fingerprint  # noqa: E402

RULES_DIR = os.path.join(ROOT, "rules")
EVENTS_PATH = os.path.join(ROOT, "data", "events.jsonl")
LABELS_PATH = os.path.join(ROOT, "labels.json")


# --------------------------------------------------------------------- helpers
def base_ts(day: int = 1, hour: int = 10, minute: int = 0, second: int = 0) -> str:
    return f"2026-10-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"


def ev(ts, account, device, action, amount=19.9, region="310000"):
    return {
        "ts": ts,
        "account": account,
        "device": device,
        "amount": amount,
        "action": action,
        "ip_region": region,
    }


def attach(events):
    """给手工事件补上引擎内部字段，模拟 load_events 的结果。"""
    from datetime import datetime

    for i, e in enumerate(events, 1):
        e["_line"] = i
        e["_dt"] = datetime.fromisoformat(e["ts"])
    return events


@pytest.fixture(scope="module")
def store():
    s = RuleStore(RULES_DIR)
    s.load()
    return s


@pytest.fixture(scope="module")
def real_events():
    return load_events(EVENTS_PATH)


@pytest.fixture(scope="module")
def labels():
    with open(LABELS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


# ----------------------------------------------------------- 数据与标签完整性
def test_events_present():
    with open(EVENTS_PATH, encoding="utf-8") as fh:
        assert sum(1 for line in fh if line.strip()) > 1000


def test_labels_present(labels):
    assert len(labels["fraud"]) >= 2
    assert {f["rule"] for f in labels["fraud"]} == {
        "burst_small_pay",
        "new_device_big_withdraw",
    }


def test_event_file_format_unchanged(real_events):
    required = {"ts", "account", "device", "amount", "action", "ip_region"}
    for e in real_events:
        assert required.issubset(e.keys())
        assert isinstance(e["amount"], (int, float))


# ----------------------------------------------------------- 规则版本化/热更新
def test_rule_store_loads_version(store):
    assert store.version == "1.0.0"
    assert set(DETECTORS) == {r["rule"] for r in store.config["rules"]}
    assert len(fingerprint(store.config)) == 12


def test_rule_versions_archived():
    versions = RuleStore(RULES_DIR).list_versions()
    assert "1.0.0" in versions
    pointer = json.load(open(os.path.join(RULES_DIR, "current.json"), encoding="utf-8"))
    assert pointer["active"] in versions


def test_hot_reload_picks_up_new_pointer(tmp_path):
    # 在临时目录构造 v1/v2 两套规则，切换指针后 store 必须无重启生效
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    v1 = {
        "version": "1.0.0",
        "rules": [
            {"rule": "burst_small_pay", "enabled": True,
             "params": {"min_count": 12, "window_seconds": 60}}
        ],
    }
    v2 = {
        "version": "2.0.0",
        "rules": [
            {"rule": "burst_small_pay", "enabled": False, "params": {}}
        ],
    }
    store = RuleStore(str(rules_dir))
    store.publish(v1)
    assert store.version == "1.0.0"
    assert store.active_rules() and store.active_rules()[0]["enabled"] is True

    store.publish(v2)  # 自动切换 current
    assert store.reload_if_changed() in (True, False)  # publish 内部已 load
    assert store.version == "2.0.0"
    assert store.active_rules() == []  # 规则被热关闭


def test_archived_versions_are_immutable(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    store = RuleStore(str(rules_dir))
    cfg = {"version": "1.0.0", "rules": [{"rule": "burst_small_pay", "params": {}}]}
    store.publish(cfg)
    with pytest.raises(FileExistsError):
        store.publish(cfg)  # 同版本不可覆盖


def test_rollback_pointer(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    store = RuleStore(str(rules_dir))
    store.publish({"version": "1.0.0", "rules": [{"rule": "burst_small_pay", "params": {}}]})
    store.publish({"version": "1.1.0", "rules": [{"rule": "burst_small_pay", "params": {}}]})
    assert store.version == "1.1.0"
    with open(rules_dir / "current.json", "w", encoding="utf-8") as fh:
        json.dump({"active": "1.0.0"}, fh)
    assert store.reload_if_changed() is True
    assert store.version == "1.0.0"


def test_invalid_config_rejected(tmp_path):
    bad = {"version": "not-semver", "rules": []}
    with pytest.raises(RuleConfigError):
        RuleStore(str(tmp_path)).publish(bad)


def test_disabled_rule_produces_no_alerts(real_events):
    cfg = {
        "version": "9.9.9",
        "rules": [
            {"rule": "burst_small_pay", "enabled": False, "params": {}},
            {"rule": "new_device_big_withdraw", "enabled": False, "params": {}},
            {"rule": "shared_device_takeover", "enabled": False, "params": {}},
        ],
    }
    assert run_engine(real_events, cfg) == []


# ----------------------------------------------------------- 真实数据：全命中零误报
def test_real_stream_labeled_fraud_all_caught(real_events, labels, store):
    alerts = run_engine(real_events, store.config)
    by_rule = {}
    for a in alerts:
        by_rule.setdefault(a["rule"], []).append(a)
    for f in labels["fraud"]:
        matched = [
            a
            for a in by_rule.get(f["rule"], [])
            if a["account"] == f["account"]
            and a["window_start"] >= f["from"]
            and a["window_end"] <= f["to"]
        ]
        assert matched, f"标注欺诈未命中: {f}"
        alert = matched[0]
        assert alert["rule_version"] == store.version
        # 告警必须含设备、账号集合、时段/地区/操作差异三类依据
        assert alert["device"]
        assert alert["accounts"]
        assert "time" in alert["evidence"]
        assert "region" in alert["evidence"]
        assert "action_diff" in alert["evidence"]


def test_real_stream_zero_false_positives(real_events, store):
    alerts = run_engine(real_events, store.config)
    fraud_accounts = {"u9001", "u9002"}
    benign = [a for a in alerts if a["account"] not in fraud_accounts]
    assert benign == [], f"正常流量出现误报: {[a['rule'] + ':' + a['account'] for a in benign]}"
    # 真实数据里没有多账号共用同一完整设备 ID，shared 规则不应触发
    assert not [a for a in alerts if a["rule"] == "shared_device_takeover"]


# --------------------------------------------------- 合成：家庭共用设备零误报
def test_family_shared_device_not_flagged(store):
    """夫妻/家人共用一台平板：白天时段、常用地区、操作习惯相似、切换有间隔。"""
    d = "home-shared-pad"
    events = attach([
        ev(base_ts(1, 9, 0, 0), "u2001", d, "login", region="310000"),
        ev(base_ts(1, 9, 3, 0), "u2001", d, "view", region="310000"),
        ev(base_ts(1, 9, 8, 0), "u2001", d, "pay", 99.0, "310000"),
        ev(base_ts(1, 9, 20, 0), "u2002", d, "login", region="310000"),  # 切换间隔 12 分钟
        ev(base_ts(1, 9, 25, 0), "u2002", d, "view", region="310000"),
        ev(base_ts(1, 9, 31, 0), "u2002", d, "pay", 49.0, "310000"),
        ev(base_ts(1, 20, 10, 0), "u2001", d, "login", region="310000"),
        ev(base_ts(1, 20, 15, 0), "u2001", d, "refund", region="310000"),
        ev(base_ts(1, 20, 40, 0), "u2002", d, "login", region="310000"),
        ev(base_ts(1, 20, 44, 0), "u2002", d, "view", region="310000"),
    ])
    # 给两个账号补足量历史（>=10 条/账号）：310000 是常用地区，操作类型混合
    history = attach([
        ev(base_ts(1, 7, 0, i), f"u200{k}", f"u200{k}-own", action, region="310000")
        for i, (k, action) in enumerate(
            [(1, "view"), (2, "view"), (1, "pay"), (2, "pay"), (1, "refund"), (2, "refund"),
             (1, "login"), (2, "login"), (1, "view"), (2, "view"), (1, "pay"), (2, "pay"),
             (1, "refund"), (2, "refund"), (1, "login"), (2, "login"), (1, "view"), (2, "view"),
             (1, "pay"), (2, "pay"), (1, "refund"), (2, "refund"), (1, "login"), (2, "login")]
        )
    ])
    alerts = DETECTORS["shared_device_takeover"](history + events, store.params("shared_device_takeover"))
    assert alerts == []
    # 评分余量锁定：家庭窗口 5 个信号全不命中，得分应为 0（阈值 6）
    from risk_engine.detectors import _score_shared_window, build_account_profiles

    profiles = build_account_profiles(history + events, 10)
    score, signals, *_ = _score_shared_window(
        [e for e in events if e["device"] == d], ["u2001", "u2002"], profiles,
        store.params("shared_device_takeover"),
    )
    assert score == 0 and signals == {}


def test_family_shared_evening_relaxed_switching_not_flagged(store):
    """晚间共用、地区一致、无秒级切换、无登录后即时风险动作：同样不能误报。"""
    d = "family-tv"
    events = attach([
        ev(base_ts(1, 21, 0, 0), "u2101", d, "login", region="110000"),
        ev(base_ts(1, 21, 6, 0), "u2101", d, "view", region="110000"),
        ev(base_ts(1, 21, 15, 0), "u2101", d, "pay", 199.0, "110000"),
        ev(base_ts(1, 21, 25, 0), "u2102", d, "login", region="110000"),
        ev(base_ts(1, 21, 30, 0), "u2102", d, "view", region="110000"),
        ev(base_ts(1, 21, 38, 0), "u2102", d, "refund", region="110000"),
    ])
    history = attach([
        ev(base_ts(1, 7, 0, i), f"u210{k}", f"u210{k}-own", action, region="110000")
        for i, (k, action) in enumerate(
            [(1, "view"), (2, "view"), (1, "pay"), (2, "pay"), (1, "refund"), (2, "refund"),
             (1, "login"), (2, "login"), (1, "view"), (2, "view"), (1, "pay"), (2, "pay"),
             (1, "refund"), (2, "refund"), (1, "login"), (2, "login"), (1, "view"), (2, "view"),
             (1, "pay"), (2, "pay"), (1, "refund"), (2, "refund"), (1, "login"), (2, "login")]
        )
    ])
    alerts = DETECTORS["shared_device_takeover"](history + events, store.params("shared_device_takeover"))
    assert alerts == []


# --------------------------------------------------- 合成：盗用设备必须命中
def test_stolen_device_takeover_flagged_with_evidence(store):
    """盗用形态：陌生设备上凌晨秒级轮登多个账号，陌生地区，登录即支付。"""
    d = "stolen-device-x"
    # 受害账号足量历史（>=10 条/账号）：只在常用地区活动、操作混合
    hist_actions_1 = ["login", "view", "pay", "refund", "view", "pay", "login", "view",
                      "refund", "pay", "view", "login"]
    hist_actions_2 = ["login", "view", "pay", "refund", "view", "pay", "login", "view",
                      "refund", "pay", "view", "login"]
    events = attach([
        ev(base_ts(1, 10, i % 50, i % 60), "u3001", "u3001-phone", a,
           region="310000" if i % 2 == 0 else "440000")
        for i, a in enumerate(hist_actions_1)
    ] + [
        ev(base_ts(1, 11, i % 50, (i + 20) % 60), "u3002", "u3002-phone", a,
           region="440000" if i % 2 == 0 else "310000")
        for i, a in enumerate(hist_actions_2)
    ] + [
        # 盗用窗口：凌晨 3 点、陌生地区 999999、同一设备秒级切号、登录后立刻 pay
        ev(base_ts(2, 3, 10, 0), "u3001", d, "login", region="999999"),
        ev(base_ts(2, 3, 10, 20), "u3001", d, "pay", 9.9, "999999"),
        ev(base_ts(2, 3, 10, 45), "u3002", d, "login", region="999999"),
        ev(base_ts(2, 3, 11, 5), "u3002", d, "withdraw", 5000.0, "999999"),
    ])
    alerts = DETECTORS["shared_device_takeover"](events, store.params("shared_device_takeover"))
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "shared_device_takeover"
    assert a["device"] == d
    assert set(a["accounts"]) == {"u3001", "u3002"}
    assert a["score"] >= a["alert_threshold"]
    # 五类信号的命中情况与三类判定依据
    assert set(a["signals"]) >= {
        "tight_switch",
        "unseen_region",
        "night_window",
        "risk_action_after_login",
    }
    assert a["evidence"]["time"]["first_ts"] == base_ts(2, 3, 10, 0)
    assert a["evidence"]["region"]["region_counts"]["999999"] >= 4
    assert "per_account_actions" in a["evidence"]["action_diff"]
    assert "u3001" in a["reason"] or "999999" in a["reason"]


def test_daytime_theft_still_caught_without_night_signal(store):
    """白天盗用：没有凌晨信号，但其余四个强信号叠加仍须过阈值。"""
    d = "daytime-hijack"
    history = attach([
        ev(base_ts(1, 9, i, 0), "u4001", "u4001-pad", action, region="310000")
        for i, action in enumerate(["login", "view", "pay", "refund", "view", "pay",
                                    "login", "view", "refund", "pay", "view", "login"])
    ] + [
        ev(base_ts(1, 9, i, 30), "u4002", "u4002-pad", action, region="310000")
        for i, action in enumerate(["login", "view", "pay", "refund", "view", "pay",
                                    "login", "view", "refund", "pay", "view", "login"])
    ])
    theft = attach([
        ev(base_ts(2, 14, 0, 0), "u4001", d, "login", region="999999"),
        ev(base_ts(2, 14, 0, 15), "u4001", d, "pay", 9.9, "999999"),
        ev(base_ts(2, 14, 0, 40), "u4002", d, "login", region="999999"),
        ev(base_ts(2, 14, 1, 0), "u4002", d, "pay", 9.9, "999999"),
    ])
    alerts = DETECTORS["shared_device_takeover"](history + theft, store.params("shared_device_takeover"))
    assert len(alerts) == 1
    assert "night_window" not in alerts[0]["signals"]
    assert alerts[0]["score"] >= alerts[0]["alert_threshold"]


def test_single_account_device_never_alerted(store):
    events = attach([
        ev(base_ts(2, 3, 0, i), "u5001", "u5001-only", action, region="999999")
        for i, action in enumerate(["login", "pay", "pay", "withdraw"])
    ])
    alerts = DETECTORS["shared_device_takeover"](events, store.params("shared_device_takeover"))
    assert alerts == []


# --------------------------------------------------- 合成：burst / new-device 边界
def test_burst_requires_full_count(store):
    params = dict(store.params("burst_small_pay"))
    events = attach([
        ev(base_ts(2, 3, 0, i), "u6001", "u6001-bot", "pay", 9.9, "999999")
        for i in range(11)  # 只有 11 笔，不够 12
    ])
    assert DETECTORS["burst_small_pay"](events, params) == []


def test_burst_spread_over_window_not_flagged(store):
    params = dict(store.params("burst_small_pay"))
    spread = attach([
        ev(f"2026-10-02T03:{m:02d}:{s:02d}", "u6003", "u6003-bot", "pay", 9.9, "999999")
        for m, s in [(0, 0), (0, 6), (0, 12), (0, 18), (0, 24), (0, 30),
                     (0, 36), (0, 42), (0, 48), (0, 54), (1, 0), (1, 6)]
    ])  # 12 笔跨度 66s，任何 60s 窗口内不足 12 笔
    assert DETECTORS["burst_small_pay"](spread, params) == []


def test_new_device_withdraw_inside_and_outside_window(store):
    params = dict(store.params("new_device_big_withdraw"))
    inside = attach([
        ev(base_ts(2, 3, 0, 0), "u7001", "u7001-new", "login", region="110000"),
        ev(base_ts(2, 3, 30, 0), "u7001", "u7001-new", "withdraw", 48000.0, "110000"),
    ])
    alerts = DETECTORS["new_device_big_withdraw"](inside, params)
    assert len(alerts) == 1 and alerts[0]["account"] == "u7001"

    outside = attach([
        ev(base_ts(2, 3, 0, 0), "u7002", "u7002-new", "login", region="110000"),
        ev(base_ts(2, 4, 1, 0), "u7002", "u7002-new", "withdraw", 48000.0, "110000"),
    ])
    assert DETECTORS["new_device_big_withdraw"](outside, params) == []


def test_known_device_withdraw_not_flagged(store):
    params = dict(store.params("new_device_big_withdraw"))
    events = attach([
        ev(base_ts(1, 9, 0, 0), "u8001", "u8001-old", "login", region="110000"),
        ev(base_ts(1, 9, 5, 0), "u8001", "u8001-old", "view", region="110000"),
        ev(base_ts(2, 9, 0, 0), "u8001", "u8001-old", "login", region="110000"),
        ev(base_ts(2, 9, 2, 0), "u8001", "u8001-old", "withdraw", 48000.0, "110000"),
    ])
    assert DETECTORS["new_device_big_withdraw"](events, params) == []


# --------------------------------------------------------------------- CLI 端到端
def run_cli(tmp_path, rules_arg=None):
    out = tmp_path / "alerts.json"
    cmd = [sys.executable, "-I", os.path.join(ROOT, "engine.py"), EVENTS_PATH, str(out)]
    if rules_arg:
        cmd += ["--rules", rules_arg]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_engine_runs_with_alert_contract(tmp_path):
    payload = run_cli(tmp_path)
    assert "alerts" in payload and payload["alerts"]
    assert payload["rule_version"] == "1.0.0"
    assert payload["rule_fingerprint"]
    for a in payload["alerts"]:
        assert a.get("account")
        assert a.get("device")
        assert isinstance(a.get("accounts"), list) and a["accounts"]
        assert a.get("reason")
        assert {"time", "region", "action_diff"}.issubset(a["evidence"])


def test_cli_hot_update_with_rules_file(tmp_path):
    # 用一份关闭全部规则的临时规则文件跑 CLI，验证 --rules 热切换
    off = tmp_path / "rules.off.json"
    off.write_text(
        json.dumps(
            {
                "version": "0.0.9",
                "rules": [
                    {"rule": "burst_small_pay", "enabled": False, "params": {}},
                    {"rule": "new_device_big_withdraw", "enabled": False, "params": {}},
                    {"rule": "shared_device_takeover", "enabled": False, "params": {}},
                ],
            }
        ),
        encoding="utf-8",
    )
    payload = run_cli(tmp_path, rules_arg=str(off))
    assert payload["rule_version"] == "0.0.9"
    assert payload["alerts"] == []
