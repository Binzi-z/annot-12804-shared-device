# 同一设备多账号登录的风控口径

家庭共用设备导致同一设备上出现多个账号，但也要识别盗用。

```
data/events.jsonl   3014 条交易事件（含 2 类欺诈）
labels.json         欺诈事件标注
engine.py           现有引擎（硬编码金额阈值，改规则要发版）
tests/              骨架测试
```

## Run

```bash
python -m pytest tests -q
python engine.py data/events.jsonl alerts.json
```

## 现状

`engine.py` 只有一条规则：金额 ≥ 10000 即告警。改一条规则要改代码、发版；
告警里也没有触发时的窗口数据，事后无法回溯。

## 需要支持的两类欺诈

| 规则 | 形态 |
|---|---|
| `burst_small_pay` | 12 payments in <60s from an unseen region |
| `new_device_big_withdraw` | login on a new device then a 48000 withdraw |

正常流量里同样有大额支付与频繁小额支付，不能只看单笔金额。
