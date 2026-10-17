import argparse
import sys
from pathlib import Path
from typing import List, Optional

from src.analysis import (
    analyze_file,
    detect_architecture,
    detect_magic,
    detect_packer,
    doctor_status,
    generate_conversion_files,
    infer_purpose,
    list_tools,
    render_analysis_text,
)
from src.config import APP_NAME, APP_VERSION, TARGET_CHOICES, ensure_output_dir, load_config, print_json, save_config


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

    out_dir = ensure_output_dir(args.output or str(Path.cwd() / "out"))
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
    print(f"\n{len(info['missing'])} tools missing but analysis can still proceed.")
    return 0


def command_version(args: argparse.Namespace) -> int:
    if getattr(args, "json", False):
        print_json({"name": APP_NAME, "version": APP_VERSION})
        return 0
    print(f"{APP_NAME} {APP_VERSION}")
    return 0


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


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
            print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        if getattr(args, "json", False):
            print_json({"error": str(exc)})
        else:
            print(f"internal error: {exc}", file=sys.stderr)
        return 2
