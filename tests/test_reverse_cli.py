import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import reverse


def test_version_flag(capsys):
    assert reverse.main(["--version"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "hrea 1.0.0"


def test_analyze_json(tmp_path, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x00\x00\x00curl http://example.com")

    assert reverse.main(["analyze", str(sample), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["file_type"] == "PE"
    assert payload["architecture"] == "x86_64"
    assert payload["purpose"] == "Network client or service"


def test_detect_command(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("#!/usr/bin/env python3\nprint('hello')\n", encoding="utf-8")

    assert reverse.main(["detect", str(sample), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["file_type"] == "script:python"
    assert payload["architecture"] == "unknown"


def test_convert_command(tmp_path, capsys):
    source = tmp_path / "source.bin"
    source.write_bytes(b"MZ")

    assert reverse.main(["convert", str(source), "-t", "python", "-o", str(tmp_path / "out"), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == "python"
    assert payload["files"] == ["main.py", "README.md"]


def test_config_round_trip(capsys):
    assert reverse.main(["config", "set", "default_target", "js", "--json"]) == 0
    assert reverse.main(["config", "get", "default_target", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["value"] == "js"


def test_doctor_json(capsys):
    assert reverse.main(["doctor", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "python" in payload
    assert "tools" in payload


def test_model_loading_path(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x00\x00\x00")
    called = {}

    def fake_load_model(model_path):
        called["path"] = model_path
        return {"loaded": True, "model_path": model_path}

    monkeypatch.setattr("src.analysis.load_model", fake_load_model)

    payload = reverse.main(["analyze", str(sample), "--model", "/tmp/test-model.gguf", "--json"])
    assert payload == 0
    assert called["path"] == "/tmp/test-model.gguf"


def test_helpers_and_generator():
    assert reverse.detect_magic(__import__("pathlib").Path("/etc/hosts")) == "unknown"
    assert reverse.detect_architecture(__import__("pathlib").Path("/etc/hosts")) == "unknown"
    generated = reverse.generate_conversion_files("python", __import__("pathlib").Path("/tmp/test.bin"), __import__("pathlib").Path("/tmp/hrea_test_out"))
    assert generated == ["main.py", "README.md"]
    assert reverse.tool_status("python")["name"] == "python"
    assert isinstance(reverse.doctor_status()["tools"], list)
