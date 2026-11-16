"""Fraud detection rules over the JSONL event stream.

事件文件格式保持不变（ts/account/device/amount/action/ip_region），引擎只做读取。

三条规则：
- ``burst_small_pay``        既有规则：陌生地区 60s 内 12 笔小额支付；
- ``new_device_big_withdraw`` 既有规则：全新设备登录后 1h 内大额提现；
- ``shared_device_takeover`` 新规则：同一物理设备出现多个账号时，用登录时段、
  地理位置、后续操作相似度区分「家庭共用」与「盗用」，多信号加权判定。

所有阈值都来自版本化规则配置（见 :mod:`risk_engine.rulestore`），代码里不写死阈值。
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

Event = Dict[str, Any]
Alert = Dict[str, Any]


# --------------------------------------------------------------------- helpers
def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def load_events(path: str) -> List[Event]:
    events: List[Event] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            event["_line"] = line_no
            event["_dt"] = parse_ts(event["ts"])
            events.append(event)
    return events


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def build_account_profiles(events: List[Event], history_min: int) -> Dict[str, Dict[str, Any]]:
    """Per-account historical profile (region/action distributions, devices)."""
    regions: Dict[str, Counter] = defaultdict(Counter)
    actions: Dict[str, Counter] = defaultdict(Counter)
    devices: Dict[str, set] = defaultdict(set)
    counts: Counter = Counter()
    for e in events:
        a = e["account"]
        counts[a] += 1
        regions[a][e["ip_region"]] += 1
        actions[a][e["action"]] += 1
        devices[a].add(e["device"])
    profiles: Dict[str, Dict[str, Any]] = {}
    for account, total in counts.items():
        profiles[account] = {
            "total": total,
            "regions": dict(regions[account]),
            "actions": dict(actions[account]),
            "devices": devices[account],
            "has_enough_history": total >= history_min,
        }
    return profiles


def _is_night(dt: datetime, night_hours: List[int]) -> bool:
    lo, hi = min(night_hours), max(night_hours)
    return lo <= dt.hour <= hi


# ------------------------------------------------------- rule 1: burst_small_pay
def detect_burst_small_pay(events: List[Event], params: Dict[str, Any]) -> List[Alert]:
    action = params.get("action", "pay")
    min_count = int(params["min_count"])
    window = int(params["window_seconds"])
    unseen_only = bool(params.get("unseen_region_only", True))
    history_min = int(params.get("history_event_min", 20))
    profiles = build_account_profiles(events, history_min)

    by_account: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e["action"] == action:
            by_account[e["account"]].append(e)

    alerts: List[Alert] = []
    for account, seq in by_account.items():
        seq.sort(key=lambda x: x["_dt"])
        left = 0
        for right in range(len(seq)):
            while (seq[right]["_dt"] - seq[left]["_dt"]).total_seconds() > window:
                left += 1
            burst = seq[left : right + 1]
            if len(burst) < min_count:
                continue
            region_counts = Counter(e["ip_region"] for e in burst)
            region, _ = region_counts.most_common(1)[0]
            reasons = [f"{window}s 窗口内 {len(burst)} 笔 {action}（阈值 {min_count}）"]
            if unseen_only:
                profile = profiles.get(account, {})
                history_share = 0.0
                if profile.get("has_enough_history"):
                    history_share = profile["regions"].get(region, 0) / profile["total"]
                is_unseen = (not profile.get("has_enough_history")) or history_share == 0.0
                reasons.append(
                    f"地区 {region} 对该账号为陌生地区（历史占比 "
                    f"{history_share:.0%}，历史事件 {profile.get('total', 0)} 条）"
                )
                if not is_unseen:
                    continue
            alerts.append(
                {
                    "rule": "burst_small_pay",
                    "account": account,
                    "accounts": sorted({e["account"] for e in burst}),
                    "device": burst[0]["device"],
                    "window_start": burst[0]["ts"],
                    "window_end": burst[-1]["ts"],
                    "lines": [e["_line"] for e in burst],
                    "evidence": {
                        "time": {
                            "window_seconds": window,
                            "event_count": len(burst),
                            "first_ts": burst[0]["ts"],
                            "last_ts": burst[-1]["ts"],
                        },
                        "region": {"ip_region": region, "region_counts": dict(region_counts)},
                        "action_diff": {"action": action, "amounts": sorted({e["amount"] for e in burst})},
                    },
                    "reason": "；".join(reasons),
                }
            )
            break  # 每个账号只报一次最早的爆发窗口
    return alerts


# ------------------------------------------------- rule 2: new_device_big_withdraw
def detect_new_device_big_withdraw(events: List[Event], params: Dict[str, Any]) -> List[Alert]:
    login_action = params.get("login_action", "login")
    risk_action = params.get("risk_action", "withdraw")
    min_amount = float(params["min_amount"])
    window = int(params["window_seconds"])

    sorted_events = sorted(events, key=lambda x: x["_dt"])
    seen_devices: set[Tuple[str, str]] = set()
    alerts: List[Alert] = []
    reported: set[Tuple[str, str]] = set()

    for e in sorted_events:
        key = (e["account"], e["device"])
        if e["action"] == login_action and key not in seen_devices:
            seen_devices.add(key)
        if (
            e["action"] == risk_action
            and float(e.get("amount", 0)) >= min_amount
            and key not in reported
        ):
            # 回溯窗口内该账号在本设备上的首次登录
            prior_logins = [
                x
                for x in sorted_events
                if x["account"] == e["account"]
                and x["device"] == e["device"]
                and x["action"] == login_action
                and 0 <= (e["_dt"] - x["_dt"]).total_seconds() <= window
            ]
            if not prior_logins:
                continue
            login = min(prior_logins, key=lambda x: x["_dt"])
            # 登录之前该账号从未在此设备出现过 => 全新设备
            appeared_before = any(
                x["account"] == e["account"]
                and x["device"] == e["device"]
                and x["_dt"] < login["_dt"]
                for x in sorted_events
            )
            if appeared_before:
                continue
            reported.add(key)
            gap = (e["_dt"] - login["_dt"]).total_seconds()
            alerts.append(
                {
                    "rule": "new_device_big_withdraw",
                    "account": e["account"],
                    "accounts": [e["account"]],
                    "device": e["device"],
                    "window_start": login["ts"],
                    "window_end": e["ts"],
                    "lines": [login["_line"], e["_line"]],
                    "evidence": {
                        "time": {
                            "login_ts": login["ts"],
                            "risk_ts": e["ts"],
                            "gap_seconds": gap,
                            "window_seconds": window,
                        },
                        "region": {
                            "login_region": login["ip_region"],
                            "risk_region": e["ip_region"],
                        },
                        "action_diff": {
                            "login_action": login_action,
                            "risk_action": risk_action,
                            "amount": e["amount"],
                            "min_amount": min_amount,
                        },
                    },
                    "reason": (
                        f"账号 {e['account']} 在全新设备 {e['device']} 上登录后 {gap:.0f}s "
                        f"发生 {risk_action} {e['amount']}（阈值 {min_amount:g}）"
                    ),
                }
            )
    return alerts


# ------------------------------------------------- rule 3: shared_device_takeover
def _merge_spans(alerts: List[Alert]) -> List[Alert]:
    """Merge overlapping windows of the same device into one span (widest range)."""
    by_device: Dict[str, List[Alert]] = defaultdict(list)
    for a in alerts:
        by_device[a["device"]].append(a)
    spans: List[Tuple[datetime, datetime, str, List[str]]] = []
    for device, group in by_device.items():
        group.sort(key=lambda x: x["_start"])
        cur_start, cur_end = group[0]["_start"], group[0]["_end"]
        cur_accounts = set(group[0]["_accounts"])
        for nxt in group[1:]:
            if nxt["_start"] <= cur_end:
                cur_end = max(cur_end, nxt["_end"])
                cur_accounts |= set(nxt["_accounts"])
            else:
                spans.append((cur_start, cur_end, device, sorted(cur_accounts)))
                cur_start, cur_end = nxt["_start"], nxt["_end"]
                cur_accounts = set(nxt["_accounts"])
        spans.append((cur_start, cur_end, device, sorted(cur_accounts)))
    return spans


def _score_shared_window(
    win: List[Event],
    win_accounts: List[str],
    profiles: Dict[str, Dict[str, Any]],
    params: Dict[str, Any],
) -> Tuple[float, Dict[str, Dict[str, Any]], Dict[str, Any], Counter, Dict[str, set], float]:
    """对一个多账号窗口计算全部信号，返回 (总分, 信号明细, 证据, 地区计数, 每账号操作, 最小相似度)。"""
    tight_seconds = int(params["tight_switch_seconds"])
    night_hours = list(params["night_hours"])
    unseen_share = float(params["unseen_region_share"])
    sim_threshold = float(params["action_similarity_threshold"])
    risk_actions = set(params["risk_actions"])
    weights = params["weights"]

    signals: Dict[str, Dict[str, Any]] = {}
    score = 0.0

    # 信号 1：紧凑账号切换（相邻事件账号不同且间隔 <= tight_seconds）
    switches = [
        (a, b, (b["_dt"] - a["_dt"]).total_seconds())
        for a, b in zip(win, win[1:])
        if a["account"] != b["account"]
    ]
    tight = [s for s in switches if s[2] <= tight_seconds]
    if tight:
        w = float(weights["tight_switch"])
        score += w
        min_gap = min(s[2] for s in tight)
        signals["tight_switch"] = {
            "hit": True,
            "weight": w,
            "switch_count": len(tight),
            "min_gap_seconds": min_gap,
            "threshold_seconds": tight_seconds,
            "detail": f"窗口内 {len(tight)} 次账号切换间隔 ≤ {tight_seconds}s，最短 {min_gap:.0f}s",
        }

    # 信号 2：陌生地区（窗口主地区在窗口账号历史中占比极低）
    region_counts = Counter(e["ip_region"] for e in win)
    main_region, main_n = region_counts.most_common(1)[0]
    region_share_in_window = main_n / len(win)
    unfamiliar_threshold = 1 - unseen_share
    unfamiliar: List[str] = []
    for account in win_accounts:
        prof = profiles[account]
        hist_share = (
            prof["regions"].get(main_region, 0) / prof["total"] if prof["total"] else 0.0
        )
        if not prof.get("has_enough_history", True) or hist_share <= unfamiliar_threshold:
            unfamiliar.append(account)
    if region_share_in_window >= unseen_share and len(unfamiliar) >= max(
        1, len(win_accounts) - 1
    ):
        w = float(weights["unseen_region"])
        score += w
        hist = {
            a: round(profiles[a]["regions"].get(main_region, 0) / profiles[a]["total"], 4)
            for a in win_accounts
        }
        signals["unseen_region"] = {
            "hit": True,
            "weight": w,
            "ip_region": main_region,
            "window_region_share": round(region_share_in_window, 4),
            "history_region_share": hist,
            "unfamiliar_accounts": unfamiliar,
            "detail": f"窗口 {region_share_in_window:.0%} 事件来自地区 {main_region}，"
            f"账号 {unfamiliar} 历史上几乎不在该地区活动",
        }

    # 信号 3：凌晨时段
    start_dt, end_dt = win[0]["_dt"], win[-1]["_dt"]
    if _is_night(start_dt, night_hours) and _is_night(end_dt, night_hours):
        w = float(weights["night_window"])
        score += w
        signals["night_window"] = {
            "hit": True,
            "weight": w,
            "start_hour": start_dt.hour,
            "night_hours": [min(night_hours), max(night_hours)],
            "detail": f"窗口整体落在凌晨 {start_dt.hour} 点档",
        }

    # 信号 4：账号间后续操作相似度低（家庭共用成员的操作习惯通常趋同）
    per_account_actions = {
        a: {e["action"] for e in win if e["account"] == a} for a in win_accounts
    }
    sims: List[float] = []
    for i, a1 in enumerate(win_accounts):
        for a2 in win_accounts[i + 1 :]:
            sims.append(_jaccard(per_account_actions[a1], per_account_actions[a2]))
    min_sim = min(sims) if sims else 1.0
    if min_sim < sim_threshold:
        w = float(weights["action_dissimilar"])
        score += w
        signals["action_dissimilar"] = {
            "hit": True,
            "weight": w,
            "min_pairwise_jaccard": round(min_sim, 4),
            "threshold": sim_threshold,
            "per_account_actions": {a: sorted(v) for a, v in per_account_actions.items()},
            "detail": f"账号间操作集合 Jaccard 相似度最低 {min_sim:.2f} < {sim_threshold}",
        }

    # 信号 5：登录后短时间内出现风险操作（pay/withdraw）
    logins = [e for e in win if e["action"] == "login"]
    risky_after: List[Dict[str, Any]] = []
    for lg in logins:
        for e in win:
            if (
                e["account"] == lg["account"]
                and e["action"] in risk_actions
                and 0 < (e["_dt"] - lg["_dt"]).total_seconds() <= tight_seconds
            ):
                risky_after.append(
                    {
                        "account": e["account"],
                        "login_ts": lg["ts"],
                        "risk_ts": e["ts"],
                        "action": e["action"],
                        "amount": e["amount"],
                        "gap_seconds": (e["_dt"] - lg["_dt"]).total_seconds(),
                    }
                )
    if risky_after:
        w = float(weights["risk_action_after_login"])
        score += w
        signals["risk_action_after_login"] = {
            "hit": True,
            "weight": w,
            "events": risky_after,
            "detail": f"{len(risky_after)} 次登录后 {tight_seconds}s 内出现 "
            f"{sorted({r['action'] for r in risky_after})} 风险操作",
        }

    evidence = {
        "time": {
            "first_ts": win[0]["ts"],
            "last_ts": win[-1]["ts"],
            "window_seconds": int(params["window_seconds"]),
            "tight_switch_seconds": tight_seconds,
        },
        "region": {"region_counts": dict(region_counts)},
        "action_diff": {
            "per_account_actions": {a: sorted(v) for a, v in per_account_actions.items()},
            "min_pairwise_jaccard": round(min_sim, 4),
        },
    }
    return score, signals, evidence, region_counts, per_account_actions, min_sim


def detect_shared_device_takeover(
    events: List[Event], params: Dict[str, Any]
) -> List[Alert]:
    """同设备多账号：家庭共用 vs 盗用。

    设备身份使用完整 ``device`` 字符串（数据中设备后缀存在随机碰撞，不能只看后缀）。
    对每个出现 >=2 个账号的设备做滑动窗口找候选片段，重叠片段合并后在完整跨度上
    统一计算 5 个信号并按权重累加；总分达到 ``alert_threshold`` 才告警，保证正常
    共用设备零误报。信号口径见 :func:`_score_shared_window`。
    """
    window = int(params["window_seconds"])
    min_accounts = int(params["min_accounts"])
    alert_threshold = float(params["alert_threshold"])
    history_min = int(params["unseen_region_history_min"])
    profiles = build_account_profiles(events, history_min)

    by_device: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        by_device[e["device"]].append(e)

    candidates: List[Alert] = []
    for device, seq in by_device.items():
        seq.sort(key=lambda x: x["_dt"])
        if len({e["account"] for e in seq}) < min_accounts:
            continue
        left = 0
        for right in range(len(seq)):
            while (seq[right]["_dt"] - seq[left]["_dt"]).total_seconds() > window:
                left += 1
            win = seq[left : right + 1]
            win_accounts = sorted({e["account"] for e in win})
            if len(win_accounts) < min_accounts:
                continue
            score, _, _, _, _, _ = _score_shared_window(win, win_accounts, profiles, params)
            if score < alert_threshold:
                continue
            candidates.append(
                {
                    "rule": "shared_device_takeover",
                    "device": device,
                    "_start": win[0]["_dt"],
                    "_end": win[-1]["_dt"],
                    "_accounts": list(win_accounts),
                }
            )

    # 合并重叠候选，再在合并后的完整跨度上重新评分，保证证据覆盖整个盗用会话
    spans = _merge_spans(candidates)
    alerts: List[Alert] = []
    for start, end, device, span_accounts in spans:
        seq = by_device[device]
        full_win = [e for e in seq if start <= e["_dt"] <= end]
        full_accounts = sorted({e["account"] for e in full_win})
        score, signals, evidence, _, _, _ = _score_shared_window(
            full_win, full_accounts, profiles, params
        )
        if score < alert_threshold:
            continue
        alerts.append(
            {
                "rule": "shared_device_takeover",
                "account": full_accounts[0],
                "accounts": full_accounts,
                "device": device,
                "window_start": full_win[0]["ts"],
                "window_end": full_win[-1]["ts"],
                "lines": sorted({e["_line"] for e in full_win}),
                "score": score,
                "alert_threshold": alert_threshold,
                "signals": signals,
                "evidence": evidence,
                "reason": "；".join(s["detail"] for s in signals.values()),
            }
        )
    alerts.sort(key=lambda x: (x["window_start"], x["device"]))
    return alerts


# --------------------------------------------------------------------- registry
DETECTORS = {
    "burst_small_pay": detect_burst_small_pay,
    "new_device_big_withdraw": detect_new_device_big_withdraw,
    "shared_device_takeover": detect_shared_device_takeover,
}


def run_engine(events: List[Event], rule_config: Dict[str, Any]) -> List[Alert]:
    alerts: List[Alert] = []
    for rule in rule_config["rules"]:
        if not rule.get("enabled", True):
            continue
        detector = DETECTORS.get(rule["rule"])
        if detector is None:
            raise KeyError(f"未知规则 {rule['rule']}（规则版本 {rule_config['version']}）")
        for alert in detector(events, rule.get("params", {})):
            alert["rule_version"] = rule_config["version"]
            alerts.append(alert)
    alerts.sort(key=lambda x: (x["window_start"], x["rule"]))
    return alerts
