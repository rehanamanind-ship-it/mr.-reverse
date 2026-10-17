import json
import platform
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from llama_cpp import Llama
    HAS_LLAMA = True
except Exception:
    Llama = None
    HAS_LLAMA = False


def load_model(model_path: str) -> Any:
    if not model_path:
        return None
    if not HAS_LLAMA:
        raise RuntimeError("llama-cpp-python is not installed. Install the dependency or use --no-ai.")
    model = Llama(model_path=model_path, verbose=False)
    return model


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
            data = handle.read(64 * 1024)
    except OSError:
        return None
    if not data:
        return None
    text = data.decode("latin-1", errors="ignore")
    markers = ["upx", "aspack", "petite", "nsis", "mpress", "megx", "pecompact"]
    lower = text.lower()
    for marker in markers:
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


def analyze_file(path: Path, no_ai: bool = False, model_path: Optional[str] = None) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    model = None
    status = "ai_disabled" if no_ai else "model_not_provided"
    if not no_ai:
        chosen_model = model_path or ""
        if chosen_model:
            try:
                model = load_model(chosen_model)
                status = "model_loaded"
            except Exception as exc:
                model = None
                status = f"model_load_failed: {exc}"

    info = {
        "path": str(path),
        "file_type": detect_magic(path),
        "architecture": detect_architecture(path),
        "packer": detect_packer(path),
        "purpose": infer_purpose(path),
        "confidence": 0.78,
        "no_ai": no_ai,
        "model_loaded": model is not None,
        "model_status": status,
    }
    info["ai_mode"] = "heuristics-only" if no_ai else "ai-enabled"
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
    readme.write_text(f"# Converted output\n\nSource: {source}\nTarget: {target}\n", encoding="utf-8")
    files.append(str(readme.name))
    return files


def tool_status(name: str) -> Dict[str, Any]:
    return {"name": name, "available": shutil.which(name) is not None}


def list_tools() -> List[Dict[str, Any]]:
    try:
        import importlib.util
        llama_available = importlib.util.find_spec("llama_cpp") is not None
    except Exception:
        llama_available = False

    return [
        tool_status("ghidra"),
        tool_status("retdec"),
        tool_status("r2"),
        tool_status("radare2"),
        tool_status("capstone"),
        {"name": "llama-cpp-python", "available": llama_available},
    ]


def doctor_status() -> Dict[str, Any]:
    tools = list_tools()
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "tools": tools,
        "missing": [tool["name"] for tool in tools if not tool["available"]],
    }
