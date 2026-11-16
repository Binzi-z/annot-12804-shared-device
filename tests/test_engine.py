import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(tmp_path):
    out = tmp_path / "alerts.json"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "engine.py"),
                        os.path.join(ROOT, "data", "events.jsonl"), str(out)],
                       capture_output=True, text=True)
    return r, out


def test_events_present():
    with open(os.path.join(ROOT, "data", "events.jsonl"), encoding="utf-8") as fh:
        n = sum(1 for _ in fh)
    assert n > 1000


def test_labels_present():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    assert len(labels["fraud"]) >= 2


def test_engine_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "alerts" in json.loads(out.read_text(encoding="utf-8"))


def test_alerts_have_account(tmp_path):
    _, out = run(tmp_path)
    for a in json.loads(out.read_text(encoding="utf-8"))["alerts"]:
        assert a.get("account")
