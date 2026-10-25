import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import reverse
from src import analysis, config
from src.cli import build_parser


def test_version_flag(capsys):
    assert reverse.main(["--version"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "hrea 1.0.1"


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


def test_load_model(tmp_path):
    assert analysis.load_model("") is None
    with pytest.raises(Exception):
        analysis.load_model(str(tmp_path / "missing.gguf"))


def test_detect_magic(tmp_path):
    samples = {
        "pe.bin": (b"MZ", "PE"),
        "elf.bin": (b"\x7fELF", "ELF"),
        "mach.bin": (b"\xfe\xed\xfa\xce", "Mach-O"),
        "script": (b"#!/usr/bin/env python3\n", "script:python"),
        "empty": (b"", "empty"),
        "unknown.bin": (b"data", "bin"),
    }
    for name, (content, expected) in samples.items():
        path = tmp_path / name
        path.write_bytes(content)
        assert analysis.detect_magic(path) == expected


def test_detect_architecture(tmp_path):
    pe = tmp_path / "x86.bin"
    pe.write_bytes(b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + (0x014C).to_bytes(2, "little"))
    elf = tmp_path / "elf.bin"
    elf_data = bytearray(b"\x7fELF" + b"\x00" * 14)
    elf_data[18:20] = (0x3E).to_bytes(2, "little")
    elf.write_bytes(elf_data)
    mach = tmp_path / "mach.bin"
    mach.write_bytes(b"\xfe\xed\xfa\xcf")
    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"data")
    assert analysis.detect_architecture(pe) == "x86"
    assert analysis.detect_architecture(elf) == "x86_64"
    assert analysis.detect_architecture(mach) == "x86_64"
    assert analysis.detect_architecture(unknown) == "unknown"


def test_detect_packer(tmp_path):
    packed = tmp_path / "packed.bin"
    plain = tmp_path / "plain.bin"
    packed.write_bytes(b"UPX packed data")
    plain.write_bytes(b"plain data")
    assert analysis.detect_packer(packed) == "UPX"
    assert analysis.detect_packer(plain) is None


def test_infer_purpose(tmp_path):
    cases = [
        (b"sqrt sin math", "Scientific calculator"),
        (b"socket https connect", "Network client or service"),
        (b"powershell exec", "Command execution utility"),
        (b"\x00\x00", "Binary payload or native executable"),
        (b"plain text", "General-purpose application"),
    ]
    for index, (content, expected) in enumerate(cases):
        path = tmp_path / f"purpose-{index}.bin"
        path.write_bytes(content)
        assert analysis.infer_purpose(path) == expected


def test_analyze_file(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ\x00\x00")
    result = analysis.analyze_file(path, no_ai=True)
    assert result["file_type"] == "PE"
    assert result["model_status"] == "ai_disabled"
    with pytest.raises(FileNotFoundError):
        analysis.analyze_file(tmp_path / "missing.bin")


def test_render_analysis_text():
    lines = analysis.render_analysis_text({
        "file_type": "PE",
        "architecture": "x86_64",
        "packer": None,
        "purpose": "test",
        "confidence": 0.78,
        "no_ai": True,
    })
    assert any(line.startswith("File type:") for line in lines)
    assert any("heuristics only" in line for line in lines)


def test_generate_conversion_files(tmp_path):
    source = tmp_path / "source.bin"
    output = tmp_path / "generated"
    source.write_bytes(b"data")
    files = analysis.generate_conversion_files("python", source, output)
    assert files == ["main.py", "README.md"]
    assert (output / "main.py").exists()
    assert (output / "README.md").exists()


def test_tool_status():
    result = analysis.tool_status("python")
    assert result["name"] == "python"
    assert result["available"] is True


def test_list_tools():
    names = {item["name"] for item in analysis.list_tools()}
    assert "llama-cpp-python" in names
    assert "capstone" in names


def test_doctor_status():
    result = analysis.doctor_status()
    assert result["python"]
    assert result["platform"]
    assert isinstance(result["missing"], list)


def test_load_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    loaded = config.load_config()
    assert loaded["default_target"] == "python"
    (tmp_path / "config.json").write_text("not json", encoding="utf-8")
    assert config.load_config()["default_target"] == "python"


def test_save_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    config.save_config({"default_target": "rust"})
    assert json.loads((tmp_path / "config.json").read_text()) == {"default_target": "rust"}


def test_print_json(capsys):
    config.print_json({"b": 2, "a": 1})
    assert capsys.readouterr().out.strip() == '{"a": 1, "b": 2}'


def test_ensure_output_dir(tmp_path):
    output = config.ensure_output_dir(str(tmp_path / "nested"))
    assert output.is_dir()


def test_config_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    assert reverse.main(["config", "set", "default_target", "go", "--json"]) == 0
    assert reverse.main(["config", "get", "default_target", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["value"] == "go"


def test_command_analyze(tmp_path, capsys):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    assert reverse.main(["analyze", str(path), "--no-ai", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["model_status"] == "ai_disabled"


def test_command_detect(tmp_path, capsys):
    path = tmp_path / "sample.py"
    path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    assert reverse.main(["detect", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["file_type"] == "script:python"


def test_command_convert(tmp_path, capsys):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data")
    assert reverse.main(["convert", str(path), "-o", str(tmp_path / "out"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["files"] == ["main.py", "README.md"]


def test_command_list_tools(capsys):
    assert reverse.main(["list-tools", "--json"]) == 0
    assert "tools" in json.loads(capsys.readouterr().out)


def test_command_doctor(capsys):
    assert reverse.main(["doctor", "--json"]) == 0
    assert "python" in json.loads(capsys.readouterr().out)


def test_command_version(capsys):
    assert reverse.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "hrea 1.0.1"


def test_build_parser():
    parser = build_parser()
    args = parser.parse_args(["analyze", "file.bin", "--model", "model.gguf", "--json"])
    assert args.command == "analyze"
    assert args.model == "model.gguf"
    assert args.json is True


def test_main(tmp_path, capsys):
    assert reverse.main(["analyze", str(tmp_path / "missing.bin"), "--json"]) == 1
    assert "File not found" in json.loads(capsys.readouterr().out)["error"]
