import json
import sys
from pathlib import Path
from typing import Any, Dict

APP_NAME = "hrea"
APP_VERSION = "1.0.0"
TARGET_CHOICES = ["python", "js", "java", "cpp", "c", "rust", "go", "asm"]

CONFIG_DIR = Path.home() / ".config" / "hrea"
CONFIG_FILE = CONFIG_DIR / "config.json"


class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    RESET = "\033[0m"


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    palette = {
        "red": Colors.RED,
        "green": Colors.GREEN,
        "yellow": Colors.YELLOW,
        "cyan": Colors.CYAN,
    }
    return f"{palette.get(color, '')}{text}{Colors.RESET}"


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


def ensure_output_dir(path: str) -> Path:
    out = Path(path)
    out.mkdir(parents=True, exist_ok=True)
    return out
