# 同一设备多账号登录的风控口径

家庭共用设备导致同一设备上出现多个账号，但也要识别盗用。

```
data/events.jsonl      3014 条交易事件（含 2 类欺诈，格式保持不变）
labels.json            欺诈事件标注
rules/                 版本化规则配置（热更新，历史版本归档不可变）
  current.json         指向当前生效版本的指针
  rules.v1.0.0.json    归档规则版本
  rulectl.py           规则发布 / 切换 / 回滚 / 列表工具
risk_engine/
  rulestore.py         规则加载、校验、热更新、版本归档
  detectors.py         三条检测规则与告警证据构造
engine.py              CLI 入口（兼容旧调用方式）
tests/                 全量回归 + 家庭共用/盗用合成样本
```

## Run

```bash
python -m pytest tests -q
python engine.py data/events.jsonl alerts.json
python engine.py data/events.jsonl alerts.json --rules rules/rules.v1.0.0.json
```

## 设备口径

事件里的 `device` 形如 `u1029-d896`。正常流量中设备后缀（`d896` 等 31 个值）
是随机分配的，不同账号的后缀大量碰撞，**不能**用后缀当物理设备身份；引擎一律
使用完整 `device` 字符串分组。正常账号的设备前缀严格等于账号本身，全流中仅两个
标注欺诈账号出现在非自有前缀的设备上（`d000-bot`、`d777-new`）。

## 三条规则

| 规则 | 判定口径 | 关键信号 |
|---|---|---|
| `burst_small_pay` | 60s 窗口内同账号 ≥12 笔 pay，且窗口主地区对该账号为陌生地区 | 时段 + 地区 |
| `new_device_big_withdraw` | 账号在从未出现过的设备上登录，1h 内发生 ≥10000 的 withdraw | 时段 + 地区 + 操作 |
| `shared_device_takeover` | 同一完整设备 ID 出现 ≥2 个账号，窗口内多信号加权评分 ≥ 阈值 | 时段 + 地区 + 操作差异 |

### 家庭共用 vs 盗用（shared_device_takeover）

对每个多账号设备做 1800s 滑动窗口，计算 5 个信号，权重与阈值全部在规则 JSON 里：

| 信号 | 盗用侧特征 | 权重 |
|---|---|---|
| `tight_switch` | 账号切换间隔 ≤300s（脚本轮号；人工共用切换更慢） | 2 |
| `unseen_region` | 窗口 ≥80% 事件来自同一地区，且该地区在账号历史占比 ≤20% | 2 |
| `night_window` | 窗口整体落在 00–05 点 | 1 |
| `action_dissimilar` | 账号间操作集合 Jaccard 相似度 <0.5 | 2 |
| `risk_action_after_login` | 登录后 300s 内出现 pay/withdraw | 2 |

总分 ≥6 才告警。家庭共用样本（白天、常用地区、操作习惯相似、切换有间隔）
5 个信号全不命中，得分 0；盗用样本命中 4–5 个信号，得分 7–9。

## 告警结构

每条告警都带设备、账号集合与三类判定依据，且记录产生它的规则版本：

```json
{
  "rule": "new_device_big_withdraw",
  "rule_version": "1.0.0",
  "device": "d777-new",
  "accounts": ["u9002"],
  "window_start": "2026-10-02T03:28:13",
  "window_end": "2026-10-02T03:28:53",
  "lines": [3013, 3014],
  "evidence": {
    "time": {"login_ts": "...", "risk_ts": "...", "gap_seconds": 40.0},
    "region": {"login_region": "999999", "risk_region": "999999"},
    "action_diff": {"risk_action": "withdraw", "amount": 48000.0}
  },
  "reason": "账号 u9002 在全新设备 d777-new 上登录后 40s 发生 withdraw 48000……"
}
```

输出文件顶层还带 `rule_fingerprint`（规则配置 SHA-256 前 12 位），事后可凭
版本号 + 指纹复现当时的判定口径。

## 规则热更新与版本保留

```bash
# 1. 复制一份规则草稿，改 version 和参数，放到 rules/ 目录外
# 2. 发布（自动归档为 rules/rules.vX.Y.Z.json 并切换 current.json 指针）
python rules/rulectl.py publish /path/to/rules.v1.1.0.json
# 3. 下次引擎运行即生效；常驻进程可调 RuleStore.reload_if_changed() 无重启加载
# 4. 回滚只是移动指针，历史归档文件不可变、不可覆盖
python rules/rulectl.py activate 1.0.0
python rules/rulectl.py list
```

- 同版本号重复发布会被拒绝（`FileExistsError`），保证历史版本不可变；
- 规则配置有结构校验（语义版本号、规则名唯一、enabled 布尔等），坏配置加载即报错；
- 也可以用 `--rules <文件>` 直接指定某一版本规则运行，便于离线复盘。

## 检测结果

对 `data/events.jsonl` 全量 3014 条事件：

- `labels.json` 标注的 2 起欺诈（u9001 burst、u9002 新设备大额提现）全部命中；
- 其余 3000 条良性事件零误报（测试 `test_real_stream_zero_false_positives` 锁定）；
- 合成的家庭共用设备零误报、盗用设备全部命中（见 `tests/test_engine.py`）。
