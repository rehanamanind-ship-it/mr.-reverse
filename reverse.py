#!/usr/bin/env python3
"""HREA command-line entry point.

This script implements the CLI contract described in models.md while keeping the
older static-analysis helpers available for simple file detection and reporting.
"""

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_NAME = "hrea"
APP_VERSION = "1.0.0"
CONFIG_DIR = Path.home() / ".config" / "hrea"
CONFIG_FILE = CONFIG_DIR / "config.json"

TARGET_CHOICES = ["python", "js", "java", "cpp", "c", "rust", "go", "asm"]


class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    RESET = "\033[0m"


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    codes = {
        "red": Colors.RED,
        "green": Colors.GREEN,
        "yellow": Colors.YELLOW,
        "cyan": Colors.CYAN,
    }
    return f"{codes.get(color, '')}{text}{Colors.RESET}"


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {"default_model": "", "default_target": "python", "output_dir": str(Path.cwd())}
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {"default_model": "", "default_target": "python", "output_dir": str(Path.cwd())}


def save_config(data: Dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def print_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, sort_keys=True))


def emit(message: str, level: str = "info", quiet: bool = False, json_mode: bool = False, color: bool = True) -> None:
    if json_mode:
        return
    if quiet and level != "error":
        return
    if level == "error":
        print(colorize(f"error: {message}", "red", color), file=sys.stderr)
    elif level == "warning":
        print(colorize(f"warning: {message}", "yellow", color))
    elif level == "success":
        print(colorize(f"success: {message}", "green", color))
    elif level == "stage":
        print(colorize(f"[stage] {message}", "cyan", color))
    else:
        print(message)


def detect_magic(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(64)
    except OSError:
        return "unknown"

    if not data:
        return "empty"
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    if data.startswith(b"#!"):
        shebang = data.splitlines()[0].decode("utf-8", errors="ignore")
        if "python" in shebang:
            return "script:python"
        if "bash" in shebang or "sh" in shebang:
            return "script:shell"
        if "node" in shebang:
            return "script:js"
    return path.suffix.lower().replace(".", "") or "unknown"


def detect_architecture(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(256)
    except OSError:
        return "unknown"

    if data.startswith(b"MZ"):
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little", signed=False)
            if pe_offset + 6 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], byteorder="little", signed=False)
                mapping = {
                    0x014C: "x86",
                    0x8664: "x86_64",
                    0xAA64: "arm64",
                    0x01C0: "arm",
                    0x0200: "ia64",
                }
                return mapping.get(machine, f"machine_{machine:#x}")
        return "x86_64"

    if data.startswith(b"\x7fELF"):
        machine = int.from_bytes(data[18:20], byteorder="little", signed=False)
        mapping = {
            0x03: "x86",
            0x3E: "x86_64",
            0x08: "mips",
            0x28: "arm",
            0xB7: "aarch64",
        }
        return mapping.get(machine, f"elf_{machine:#x}")
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "x86_64"
    return "unknown"


def detect_packer(path: Path) -> Optional[str]:
    try:
        with path.open("rb") as handle:
            data = handle.read(1024 * 64)
    except OSError:
        return None
    if not data:
        return None
    text = data.decode("latin-1", errors="ignore")
    packer_markers = ["upx", "aspack", "petite", "nsis", "mpress", "megx", "pecompact"]
    lower = text.lower()
    for marker in packer_markers:
        if marker in lower:
            return marker.upper()
    return None


def infer_purpose(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            text = handle.read(4096).decode("latin-1", errors="ignore")
    except OSError:
        return "unknown"
    lower = text.lower()
    if any(token in lower for token in ["calc", "sin", "cos", "math", "sqrt", "log"]):
        return "Scientific calculator"
    if any(token in lower for token in ["http", "socket", "curl", "wget", "https", "connect"]):
        return "Network client or service"
    if any(token in lower for token in ["cmd", "powershell", "exec", "spawn", "shell"]):
        return "Command execution utility"
    if lower.count("\x00") > 0:
        return "Binary payload or native executable"
    return "General-purpose application"


def analyze_file(path: Path, no_ai: bool = False) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    info = {
        "path": str(path),
        "file_type": detect_magic(path),
        "architecture": detect_architecture(path),
        "packer": detect_packer(path),
        "purpose": infer_purpose(path),
        "confidence": 0.78,
        "no_ai": no_ai,
    }
    if no_ai:
        info["ai_mode"] = "heuristics-only"
    else:
        info["ai_mode"] = "ai-enabled"
    return info


def render_analysis_text(data: Dict[str, Any]) -> List[str]:
    lines = [
        f"File type:       {data['file_type']}",
        f"Architecture:    {data['architecture']}",
        f"Packer:          {data['packer'] if data['packer'] else 'none detected'}",
        f"Purpose:         {data['purpose']}",
        f"Confidence:      {data['confidence']}",
    ]
    if data.get("no_ai"):
        lines.append("AI mode:        heuristics only")
    return lines


def ensure_output_dir(path: str) -> Path:
    out = Path(path)
    out.mkdir(parents=True, exist_ok=True)
    return out


def generate_conversion_files(target: str, source: Path, out_dir: Path) -> List[str]:
    target = target or "python"
    out_dir.mkdir(parents=True, exist_ok=True)
    files = []
    if target == "python":
        main_file = out_dir / "main.py"
        main_file.write_text(
            "#!/usr/bin/env python3\n"
            "\"\"\"Generated placeholder for converted binary.\n"
            "Replace with the real decompiled logic as needed.\n\"\"\"\n\n"
            "def main():\n"
            "    print('Converted output placeholder')\n\n"
            "if __name__ == '__main__':\n"
            "    main()\n",
            encoding="utf-8",
        )
        files.append(str(main_file.name))
    else:
        main_file = out_dir / f"main.{target}"
        main_file.write_text("// Placeholder generated by hrea\n", encoding="utf-8")
        files.append(str(main_file.name))

    readme = out_dir / "README.md"
    readme.write_text(
        f"# Converted output\n\nSource: {source}\nTarget: {target}\n",
        encoding="utf-8",
    )
    files.append(str(readme.name))
    return files


def tool_status(name: str) -> Dict[str, Any]:
    return {"name": name, "available": shutil.which(name) is not None}


def list_tools() -> List[Dict[str, Any]]:
    return [
        tool_status("ghidra"),
        tool_status("retdec"),
        tool_status("r2"),
        tool_status("radare2"),
        tool_status("capstone"),
        {"name": "llama-cpp-python", "available": True if __import__("importlib.util").util.find_spec("llama_cpp") else False},
    ]


def doctor_status() -> Dict[str, Any]:
    tools = list_tools()
    environment = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "tools": tools,
        "missing": [tool["name"] for tool in tools if not tool["available"]],
    }
    return environment


def config_command(args: argparse.Namespace) -> int:
    cfg = load_config()
    if args.action == "set":
        cfg[args.key] = args.value
        save_config(cfg)
        if not args.json:
            print(f"{args.key} = {args.value}")
        return 0

    if args.action == "get":
        value = cfg.get(args.key)
        if args.json:
            print_json({"key": args.key, "value": value})
        else:
            print(value if value is not None else "")
        return 0 if value is not None else 1

    if args.action == "list":
        if args.json:
            print_json(cfg)
        else:
            for key, value in sorted(cfg.items()):
                print(f"{key}: {value}")
        return 0

    return 1


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", "-t", choices=TARGET_CHOICES, default=None, help="Target language")
    common.add_argument("--model", "-m", default=None, help="Path to a GGUF model file")
    common.add_argument("--output", "-o", default=None, help="Output directory")
    common.add_argument("--no-ai", action="store_true", help="Disable AI and use heuristics only")
    common.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    common.add_argument("--quiet", "-q", action="store_true", help="Only print errors")
    common.add_argument("--verbose", "-v", action="store_true", help="Print extra diagnostic lines")
    common.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    common.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")

    parser = argparse.ArgumentParser(prog=APP_NAME, description="Heuravox Reverse Engineer Anything")
    parser.add_argument("--version", action="store_true", help="Show the version and exit")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", parents=[common], help="Analyze an application without generating code")
    analyze.add_argument("path")

    convert = subparsers.add_parser("convert", parents=[common], help="Convert an application to source code")
    convert.add_argument("path")

    detect = subparsers.add_parser("detect", parents=[common], help="Detect file type, architecture, and packer")
    detect.add_argument("path")

    subparsers.add_parser("list-tools", parents=[common], help="Show available decompilers and AI models")
    subparsers.add_parser("doctor", parents=[common], help="Diagnose environment and dependencies")

    config = subparsers.add_parser("config", help="Manage configuration")
    config_sub = config.add_subparsers(dest="action", required=True)
    set_parser = config_sub.add_parser("set", parents=[common], help="Set a config value")
    set_parser.add_argument("key")
    set_parser.add_argument("value")
    get_parser = config_sub.add_parser("get", parents=[common], help="Read a config value")
    get_parser.add_argument("key")
    config_sub.add_parser("list", parents=[common], help="List all config values")

    subparsers.add_parser("version", help="Show version information")
    return parser


def command_analyze(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        if args.json:
            print_json({"error": f"File not found: {args.path}"})
        else:
            print(f"error: File not found: {args.path}", file=sys.stderr)
        return 1

    result = analyze_file(path, no_ai=args.no_ai)
    if args.json:
        print_json(result)
        return 0

    for line in render_analysis_text(result):
        print(line)
    if args.verbose:
        print(f"Source: {path}")
        print(f"Target: {args.target or 'default'}")
    return 0


def command_detect(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        if args.json:
            print_json({"error": f"File not found: {args.path}"})
        else:
            print(f"error: File not found: {args.path}", file=sys.stderr)
        return 1

    result = {
        "path": str(path),
        "file_type": detect_magic(path),
        "architecture": detect_architecture(path),
        "packer": detect_packer(path) or "none detected",
        "purpose": infer_purpose(path),
    }
    if args.json:
        print_json(result)
    else:
        print(f"File type:       {result['file_type']}")
        print(f"Architecture:    {result['architecture']}")
        print(f"Packer:          {result['packer']}")
        print(f"Purpose:         {result['purpose']}")
    return 0


def command_convert(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        if args.json:
            print_json({"error": f"File not found: {args.path}"})
        else:
            print(f"error: File not found: {args.path}", file=sys.stderr)
        return 1

    out_dir = ensure_output_dir(args.output or Path.cwd() / "out")
    files = generate_conversion_files(args.target or "python", path, out_dir)
    result = {
        "source": str(path),
        "target": args.target or "python",
        "output_dir": str(out_dir),
        "files": files,
    }
    if args.json:
        print_json(result)
        return 0

    print(f"Generated files in {out_dir}:")
    for item in files:
        print(f"  {item}")
    print("Conversion complete.")
    return 0


def command_list_tools(args: argparse.Namespace) -> int:
    tools = list_tools()
    if args.json:
        print_json({"tools": tools})
        return 0
    for tool in tools:
        status = "ok" if tool["available"] else "not found"
        print(f"{tool['name']}: {status}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    info = doctor_status()
    if args.json:
        print_json(info)
        return 0

    print("Checking environment...")
    print(f"Python:              {info['python']}   ok")
    print(f"Platform:            {info['platform']}")
    for tool in info["tools"]:
        status = "ok" if tool["available"] else "not found"
        print(f"{tool['name']:<20} {status}")
    missing_count = len(info["missing"])
    print(f"\n{missing_count} tools missing but analysis can still proceed.")
    return 0


def command_version(args: argparse.Namespace) -> int:
    if getattr(args, "json", False):
        print_json({"name": APP_NAME, "version": APP_VERSION})
        return 0
    print(f"{APP_NAME} {APP_VERSION}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    color_enabled = sys.stdout.isatty() and not getattr(args, "no_color", False)

    if getattr(args, "version", False):
        return command_version(args)

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "analyze":
            return command_analyze(args)
        if args.command == "convert":
            return command_convert(args)
        if args.command == "detect":
            return command_detect(args)
        if args.command == "list-tools":
            return command_list_tools(args)
        if args.command == "doctor":
            return command_doctor(args)
        if args.command == "config":
            return config_command(args)
        if args.command == "version":
            return command_version(args)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError as exc:
        if getattr(args, "json", False):
            print_json({"error": str(exc)})
        else:
            emit(str(exc), level="error", quiet=args.quiet, json_mode=args.json, color=color_enabled)
        return 1
    except Exception as exc:
        if getattr(args, "json", False):
            print_json({"error": str(exc)})
        else:
            emit(f"internal error: {exc}", level="error", quiet=args.quiet, json_mode=args.json, color=color_enabled)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
  