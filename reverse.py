#!/usr/bin/env python3
"""Compatibility wrapper for the real HREA implementation.

The project is split under src/, but older scripts and tests still import
reverse.py directly. This module re-exports the real functionality so runtime and
tests exercise the same code path.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Sequence

from src.analysis import (
    analyze_file,
    detect_architecture,
    detect_magic,
    detect_packer,
    doctor_status,
    generate_conversion_files,
    infer_purpose,
    load_model,
    render_analysis_text,
    tool_status,
)
from src.cli import build_parser, config_command, command_analyze, command_convert, command_detect, command_doctor, command_list_tools, command_version, main as _cli_main
from src.config import APP_NAME, APP_VERSION, CONFIG_DIR, CONFIG_FILE, TARGET_CHOICES, ensure_output_dir, emit, load_config, print_json, save_config

# Backward-compatible aliases used by older callers and tests.
detect = command_detect
config = config_command


def main(argv: Optional[Sequence[str]] = None) -> int:
    return _cli_main(list(argv) if argv is not None else None)


if __name__ == "__main__":
    raise SystemExit(main())
  