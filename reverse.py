#!/usr/bin/env python3
"""
demon.py - Colourful curses CLI for EXE/script intent analysis.
Banner: D.E.M.O.N. in red, "made by rehan aman" below.
Follows DRY, ETC, and is fully commented.
"""

import os
import sys
import json
import hashlib
import math
import struct
import time
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, asdict

# ---------- Binary parsing (optional) ----------
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    HAS_ELFFILE = True
except ImportError:
    HAS_ELFFILE = False

try:
    from macholib.MachO import MachO
    from macholib.mach_o import LC_LOAD_DYLIB
    HAS_MACHOLIB = True
except ImportError:
    HAS_MACHOLIB = False

try:
    import dnfile
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

# ---------- AI (GGUF) ----------
try:
    from llama_cpp import Llama
    HAS_LLAMA = True
except ImportError:
    HAS_LLAMA = False

# ---------- Curses ----------
import curses
from curses import wrapper, textpad

# ============================================================================
# CONSTANTS & PATHS
# ============================================================================
APP_NAME = "D.E.M.O.N."
CONFIG_FILE = Path(__file__).parent / "config.json"
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
LOG_FILE = Path(__file__).parent / "analyser.log"

# ============================================================================
# LOGGING
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION (dataclass)
# ============================================================================
@dataclass
class Config:
    """
    Persistent configuration for the analyser.
    Stores model path, keywords, thresholds, AI params, and cache toggle.
    """
    default_model: Optional[str] = None
    suspicious_keywords: List[str] = None
    max_strings: int = 30
    entropy_threshold: float = 7.0
    cache_enabled: bool = True
    ai_params: Dict[str, Any] = None

    def __post_init__(self):
        """Set default lists/dicts if not provided."""
        if self.suspicious_keywords is None:
            self.suspicious_keywords = [
                "http", "www.", "cmd", "powershell", "/etc/", "temp", "passwd",
                "CreateRemoteThread", "VirtualAlloc", "RegOpenKey", "WMI",
                "ShellExecute", "WinExec", "GetProcAddress", "LoadLibrary"
            ]
        if self.ai_params is None:
            self.ai_params = {
                "max_tokens": 150,
                "temperature": 0.3,
                "top_p": 0.9,
                "n_gpu_layers": -1,   # -1 = use all GPU layers
                "verbose": False
            }

    @classmethod
    def load(cls) -> 'Config':
        """Load config from JSON file; return defaults if missing."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    return cls(**data)
            except Exception as e:
                logger.warning(f"Could not load configuration: {e}. Using defaults.")
        return cls()

    def save(self) -> None:
        """Save config to JSON file."""
        with open(CONFIG_FILE, "w") as f:
            json.dump(asdict(self), f, indent=2)


# ============================================================================
# UTILITY FUNCTIONS (pure, stateless)
# ============================================================================
def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract all ASCII strings of at least min_len characters."""
    strings = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings


def filter_suspicious(strings: List[str], keywords: List[str], limit: int) -> List[str]:
    """
    Return strings that contain any keyword (case‑insensitive).
    Deduplicates and limits results according to the configuration.
    """
    result = []
    for s in strings:
        lower = s.lower()
        if any(k.lower() in lower for k in keywords):
            result.append(s)
    return sorted(set(result))[:limit]


# ============================================================================
# STATIC ANALYSIS (format‑specific)
# ============================================================================
def analyse_pe(data: bytes) -> Dict[str, Any]:
    """
    Parse PE (Portable Executable) and extract:
      - entry point, imports, section names/entropies.
    Falls back to manual parsing if pefile not available.
    """
    info = {"format": "PE", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_PEFILE:
        # Manual fallback for entry point
        try:
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            if data[e_lfanew:e_lfanew+4] == b'PE\0\0':
                info["entry"] = struct.unpack("<I", data[e_lfanew+0x28:e_lfanew+0x2C])[0]
        except Exception:
            pass
        return info

    try:
        pe = pefile.PE(data=data)
        info["entry"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        info["imports"].append(f"{dll}!{imp.name.decode('utf-8', errors='ignore')}")
        for section in pe.sections:
            sec_data = section.get_data()
            entropy = compute_entropy(sec_data)
            info["sections"].append({
                "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                "virtual_size": section.Misc_VirtualSize,
                "entropy": entropy
            })
            info["entropy"] = max(info["entropy"], entropy)
    except Exception as e:
        logger.error(f"PE analysis error: {e}")
    return info


def analyse_elf(data: bytes) -> Dict[str, Any]:
    """
    Parse ELF and extract entry, needed libraries (imports), section entropies.
    Falls back to manual entry point if pyelftools not available.
    """
    info = {"format": "ELF", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_ELFFILE:
        try:
            if data[4] == 2:   # 64-bit
                info["entry"] = struct.unpack("<Q", data[0x18:0x20])[0]
            else:              # 32-bit
                info["entry"] = struct.unpack("<I", data[0x18:0x1C])[0]
        except Exception:
            pass
        return info

    try:
        from io import BytesIO
        elffile = ELFFile(BytesIO(data))
        info["entry"] = elffile.header.e_entry
        for section in elffile.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        if hasattr(tag, 'needed'):
                            needed = tag.needed
                            info["imports"].append(
                                needed.decode('utf-8', errors='ignore') if isinstance(needed, bytes) else str(needed)
                            )
        for section in elffile.iter_sections():
            sec_data = section.data()
            entropy = compute_entropy(sec_data)
            info["sections"].append({
                "name": section.name,
                "size": section['sh_size'],
                "entropy": entropy
            })
            info["entropy"] = max(info["entropy"], entropy)
    except Exception as e:
        logger.error(f"ELF analysis error: {e}")
    return info


def analyse_macho(path: Path) -> Dict[str, Any]:
    """
    Parse Mach‑O and extract imported dylibs.
    Entropy and entry point are not fully extracted in this stub.
    """
    info = {"format": "Mach-O", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_MACHOLIB:
        return info
    try:
        macho = MachO(str(path))
        for header in macho.headers:
            for load_cmd, _, dylib_data in header.commands:
                if load_cmd.cmd == LC_LOAD_DYLIB and dylib_data:
                    if isinstance(dylib_data, bytes):
                        dylib_data = dylib_data.split(b'\0', 1)[0].decode('utf-8', errors='ignore')
                    info["imports"].append(str(dylib_data))
    except Exception as e:
        logger.error(f"Mach-O analysis error: {e}")
    return info


def analyse_dotnet(data: bytes) -> Dict[str, Any]:
    """
    Parse .NET assembly (PE with CLR header) and extract assembly name.
    """
    info = {"format": ".NET", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_DNFILE:
        return info
    try:
        pe = dnfile.dnPE(data=data)
        info["entry"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        assembly_table = getattr(getattr(pe.net, "mdtables", None), "Assembly", None)
        rows = getattr(assembly_table, "rows", [])
        if rows:
            info["imports"] = [f"Assembly: {rows[0].Name}"]
    except Exception as e:
        logger.error(f".NET analysis error: {e}")
    return info


def is_dotnet_assembly(data: bytes) -> bool:
    """Identify PE files with a CLR header when dnfile is available."""
    if not HAS_DNFILE:
        return False
    try:
        return getattr(dnfile.dnPE(data=data), "net", None) is not None
    except Exception:
        return False


def detect_script(data: bytes) -> Optional[str]:
    """Detect shebang‑based scripts (Python, Bash, Perl, Ruby, Node)."""
    if data.startswith(b'#!'):
        line = data.split(b'\n')[0].decode('utf-8', errors='ignore')
        if 'python' in line:
            return 'Python'
        elif 'bash' in line or 'sh' in line:
            return 'Shell'
        elif 'perl' in line:
            return 'Perl'
        elif 'ruby' in line:
            return 'Ruby'
        elif 'node' in line:
            return 'JavaScript'
    return None


def static_analysis(path: Path, config: Config) -> Tuple[str, Dict[str, Any]]:
    """
    Orchestrate format detection and run the appropriate analyser.
    Returns a human‑readable report string and a structured info dict.
    """
    with open(path, "rb") as f:
        data = f.read()

    # Detect format
    info = {}
    format_name = "Unknown"
    if data[:2] == b'MZ':
        if is_dotnet_assembly(data):
            format_name = ".NET"
            info = analyse_dotnet(data)
        else:
            format_name = "PE"
            info = analyse_pe(data)
    elif data[:4] == b'\x7fELF':
        format_name = "ELF"
        info = analyse_elf(data)
    elif data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        format_name = "Mach-O"
        info = analyse_macho(path)
    else:
        script_type = detect_script(data)
        if script_type:
            format_name = f"Script ({script_type})"
        else:
            format_name = "Data"

    all_strings = extract_ascii_strings(data)
    suspicious = filter_suspicious(all_strings, config.suspicious_keywords, config.max_strings)

    # Build the report
    report_lines = [f"Format: {format_name}"]
    if info.get('entry') is not None:
        report_lines.append(f"Entry point: 0x{info['entry']:X}")
    if info.get('imports'):
        report_lines.append("\nImported symbols (first 30):")
        for imp in info['imports'][:30]:
            report_lines.append(f"  {imp}")
    if info.get('sections'):
        report_lines.append("\nSections (name, entropy):")
        for sec in info['sections'][:20]:
            report_lines.append(f"  {sec.get('name', '?')}: entropy = {sec.get('entropy', 0.0):.2f}")
        if info.get('entropy', 0.0) > config.entropy_threshold:
            report_lines.append("** High entropy detected – possible packing/encryption **")
    if suspicious:
        report_lines.append(f"\nSuspicious strings (found {len(suspicious)}):")
        for s in suspicious:
            report_lines.append(f"  {s}")
    else:
        report_lines.append("\nNo suspicious strings found.")

    report_str = "\n".join(report_lines)
    info['format'] = format_name
    info['suspicious_strings'] = suspicious
    info['all_strings_count'] = len(all_strings)
    info['file_size'] = len(data)
    info['sha256'] = hashlib.sha256(data).hexdigest()
    return report_str, info


# ============================================================================
# AI INTEGRATION (GGUF)
# ============================================================================
_llama = None   # Global model instance

def load_model(model_path: str, config: Config) -> None:
    """
    Load a GGUF model using llama-cpp-python.
    Uses parameters from config.ai_params.
    """
    global _llama
    if not HAS_LLAMA:
        logger.warning("llama-cpp-python not installed – AI disabled.")
        _llama = None
        return
    try:
        params = config.ai_params
        _llama = Llama(
            model_path=model_path,
            n_gpu_layers=params.get('n_gpu_layers', -1),
            verbose=params.get('verbose', False)
        )
        logger.info(f"Model loaded: {model_path}")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        _llama = None


def ai_analyse(report: str, config: Config) -> str:
    """
    Run the loaded model on the static report and return a verdict.
    Returns an error message if model not loaded or llama missing.
    """
    if _llama is None:
        if HAS_LLAMA:
            return "Error: No model loaded. Please select a GGUF model."
        else:
            return "Error: llama-cpp-python not installed."

    prompt = (
        "You are a security analyst. Given the following static analysis report of a binary, "
        "determine the likely intent (malicious, benign, or suspicious). "
        "Provide a concise explanation.\n\n"
        f"Report:\n{report}\n\nIntent:"
    )
    try:
        response = _llama(
            prompt,
            max_tokens=config.ai_params.get('max_tokens', 150),
            temperature=config.ai_params.get('temperature', 0.3),
            top_p=config.ai_params.get('top_p', 0.9),
            stop=["\n\n"],
            echo=False
        )
        return response['choices'][0]['text'].strip()
    except Exception as e:
        logger.error(f"Inference error: {e}")
        return f"Inference failed: {e}"


# ============================================================================
# CACHING (SHA‑256 based)
# ============================================================================
def get_cache_path(cache_key: str) -> Path:
    """Return the cache file path for a file and analysis-settings key."""
    return CACHE_DIR / f"{cache_key}.json"


def get_cache_key(sha256: str, config: Config) -> str:
    """Bind cached verdicts to the relevant static-analysis and AI settings."""
    model = {"path": config.default_model}
    if config.default_model:
        try:
            stat = Path(config.default_model).stat()
            model.update({"size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
        except OSError:
            model["unavailable"] = True
    settings = {
        "version": 2,
        "sha256": sha256,
        "keywords": config.suspicious_keywords,
        "max_strings": config.max_strings,
        "entropy_threshold": config.entropy_threshold,
        "ai_params": config.ai_params,
        "model": model,
    }
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode("utf-8")).hexdigest()


def cache_result(cache_key: str, sha256: str, report: str, info: Dict[str, Any], ai_verdict: str) -> None:
    """Store analysis result in cache as JSON."""
    cache_path = get_cache_path(cache_key)
    data = {
        "sha256": sha256,
        "report": report,
        "info": info,
        "ai_verdict": ai_verdict,
        "timestamp": time.time()
    }
    with open(cache_path, "w") as f:
        json.dump(data, f, indent=2)


def load_cache(cache_key: str) -> Optional[Dict[str, Any]]:
    """Load cached result if it exists; return None otherwise."""
    cache_path = get_cache_path(cache_key)
    if cache_path.exists():
        try:
            with open(cache_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Ignoring unreadable cache entry: {e}")
    return None


def analyse_file(file_path: Path, config: Config, use_cache: bool = True) -> Dict[str, Any]:
    """
    Master pipeline: static analysis, AI inference, and caching.
    Returns a dict with report, info, ai_verdict, sha256, timestamp.
    """
    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
    cache_key = get_cache_key(sha256, config)
    if use_cache and config.cache_enabled:
        cached = load_cache(cache_key)
        if cached:
            logger.info("Using cached result")
            return cached

    report_str, info = static_analysis(file_path, config)
    ai_verdict = ai_analyse(report_str, config)
    result = {
        "sha256": sha256,
        "report": report_str,
        "info": info,
        "ai_verdict": ai_verdict,
        "timestamp": time.time()
    }
    if config.cache_enabled:
        cache_result(cache_key, sha256, report_str, info, ai_verdict)
    return result



 # ============================================================================
# CURSES APPLICATION
# ============================================================================
class CursesApp:
    """
    Main interactive curses interface for D.E.M.O.N.
    Displays a banner, menu, and scrollable analysis results.
    All popups have fallback for small terminals.
    """

    def __init__(self, stdscr, config: Config):
        self.stdscr = stdscr
        self.config = config
        self.current_result = None
        self.scroll_offset = 0
        self.report_lines = []

        # Setup colours
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)      # Title / errors
        curses.init_pair(2, curses.COLOR_GREEN, -1)    # Success / benign
        curses.init_pair(3, curses.COLOR_YELLOW, -1)   # Warnings
        curses.init_pair(4, curses.COLOR_CYAN, -1)     # Info
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # Highlights
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Selected menu

        self.rows, self.cols = stdscr.getmaxyx()
        self.menu = [
            ("Analyse", self.analyse),
            ("Select Model", self.select_model),
            ("Toggle Cache", self.toggle_cache),
            ("Exit", self.exit_app)
        ]
        self.current_selection = 0
        self.running = True

        # Load default model if present
        if self.config.default_model and Path(self.config.default_model).exists():
            load_model(self.config.default_model, self.config)

    def run(self):
        """Main event loop."""
        while self.running:
            self.stdscr.clear()
            self.draw_header()
            self.draw_menu()
            self.draw_content()
            self.stdscr.refresh()
            key = self.stdscr.getch()
            self.handle_key(key)

    def handle_key(self, key):
        """Handle keyboard input with scroll support for reports."""
        if self.current_result and key in (27, curses.KEY_BACKSPACE, 127):
            self.current_result = None
            self.report_lines = []
            self.scroll_offset = 0
        elif key == curses.KEY_UP:
            if self.current_result:
                self.scroll_offset = max(0, self.scroll_offset - 1)
            else:
                self.current_selection = (self.current_selection - 1) % len(self.menu)
        elif key == curses.KEY_DOWN:
            if self.current_result:
                max_scroll = max(0, len(self.report_lines) - self.available_lines())
                self.scroll_offset = min(max_scroll, self.scroll_offset + 1)
            else:
                self.current_selection = (self.current_selection + 1) % len(self.menu)
        elif key == ord('\n') or key == ord(' '):
            if not self.current_result:
                _, action = self.menu[self.current_selection]
                action()
        elif key == ord('q') or key == ord('Q'):
            self.running = False

    def available_lines(self) -> int:
        """Number of lines available for content display."""
        return max(1, self.rows - 12)

    def draw_header(self):
        """Draw the big red banner and credit line."""
        title = "D.E.M.O.N."
        credit = "made by rehan aman"
        x_title = (self.cols - len(title)) // 2
        x_credit = (self.cols - len(credit)) // 2
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(1, x_title, title)
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(2, x_credit, credit)
        self.stdscr.attroff(curses.color_pair(4))

        # Separator line
        self.stdscr.attron(curses.color_pair(3))
        self.stdscr.hline(3, 1, curses.ACS_HLINE, self.cols - 2)
        self.stdscr.attroff(curses.color_pair(3))

    def draw_menu(self):
        """Draw the main menu and status info (model, cache)."""
        y = 5
        x = 2
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(y, x, "Main Menu:")
        self.stdscr.attroff(curses.color_pair(4))
        y += 1
        for idx, (label, _) in enumerate(self.menu):
            if idx == self.current_selection:
                self.stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                self.stdscr.addstr(y, x, f" > {label}")
                self.stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
            else:
                self.stdscr.addstr(y, x, f"   {label}")
            y += 1

        # Show current model
        model_path = self.config.default_model or "None"
        model_display = f"Model: {model_path[:40]}{'...' if len(model_path)>40 else ''}"
        self.stdscr.attron(curses.color_pair(3))
        self.stdscr.addstr(y + 1, x, model_display.ljust(self.cols - x - 2))
        self.stdscr.attroff(curses.color_pair(3))

        # Show cache status
        cache_status = "Cache: ON" if self.config.cache_enabled else "Cache: OFF"
        self.stdscr.attron(curses.color_pair(5))
        self.stdscr.addstr(y + 2, x, cache_status)
        self.stdscr.attroff(curses.color_pair(5))

    def draw_content(self):
        """Display the analysis result or instructions, with scroll indicators."""
        start_y = 10
        if self.current_result:
            # Build report lines if not cached
            if not self.report_lines:
                full_report = self.current_result['report'] + "\n\nAI Verdict:\n" + self.current_result['ai_verdict']
                self.report_lines = full_report.splitlines()

            max_lines = self.available_lines()
            visible = self.report_lines[self.scroll_offset:self.scroll_offset + max_lines]
            for i, line in enumerate(visible):
                # Colourise based on content
                if "suspicious" in line.lower() or "malicious" in line.lower():
                    color = curses.color_pair(1)
                elif "benign" in line.lower() or "no obvious" in line.lower():
                    color = curses.color_pair(2)
                elif "error" in line.lower():
                    color = curses.color_pair(1)
                elif "high entropy" in line.lower():
                    color = curses.color_pair(3)
                elif "AI Verdict" in line:
                    color = curses.color_pair(5) | curses.A_BOLD
                else:
                    color = curses.color_pair(0)
                self.stdscr.attron(color)
                self.stdscr.addstr(start_y + i, 2, line[:self.cols - 4])
                self.stdscr.attroff(color)

            # Scroll indicators
            if self.scroll_offset > 0:
                self.stdscr.attron(curses.color_pair(3))
                self.stdscr.addstr(start_y, self.cols - 2, "▲")
                self.stdscr.attroff(curses.color_pair(3))
            if self.scroll_offset + max_lines < len(self.report_lines):
                self.stdscr.attron(curses.color_pair(3))
                self.stdscr.addstr(start_y + max_lines - 1, self.cols - 2, "▼")
                self.stdscr.attroff(curses.color_pair(3))
        else:
            self.stdscr.attron(curses.color_pair(4))
            self.stdscr.addstr(start_y, 2, "Select 'Analyse' to scan a file.")
            self.stdscr.attroff(curses.color_pair(4))

    # ---------- Safe Input/Message Popups ----------
    def prompt_path(self, title: str) -> Optional[str]:
        """
        Show a popup to input a file path.
        Falls back to inline input if terminal is too small.
        """
        height = 5
        width = min(60, self.cols - 4)
        # Check if we have enough space for a popup
        if self.rows < height + 4 or self.cols < width + 4:
            return self._inline_input(title)

        y = (self.rows - height) // 2
        x = (self.cols - width) // 2
        try:
            win = curses.newwin(height, width, y, x)
        except curses.error:
            return self._inline_input(title)

        win.border(0)
        win.attron(curses.color_pair(4))
        win.addstr(0, 2, title[:width-4])
        win.attroff(curses.color_pair(4))
        win.addstr(2, 2, "Path: ")
        curses.echo()
        try:
            path = win.getstr(2, 8, width - 10).decode('utf-8')
        except curses.error:
            path = ""
        curses.noecho()
        return path.strip()

    def _inline_input(self, title: str) -> str:
        """Fallback: prompt directly on the main screen."""
        self.stdscr.clear()
        self.draw_header()
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(10, 2, f"{title} (type path): ")
        self.stdscr.attroff(curses.color_pair(4))
        curses.echo()
        path = self.stdscr.getstr(10, len(f"{title} (type path): ") + 2, self.cols - 10).decode('utf-8')
        curses.noecho()
        self.stdscr.refresh()
        return path.strip()

    def show_message(self, msg: str, is_error: bool = False, wait: bool = False):
        """
        Display a temporary popup message.
        Falls back to a one‑line display on the main screen if terminal is too small.
        """
        height = 5
        width = min(len(msg) + 10, self.cols - 4)
        if self.rows < height + 4 or self.cols < width + 4:
            self._inline_message(msg, is_error, wait)
            return

        y = (self.rows - height) // 2
        x = (self.cols - width) // 2
        try:
            win = curses.newwin(height, width, y, x)
        except curses.error:
            self._inline_message(msg, is_error, wait)
            return

        win.border(0)
        if is_error:
            win.attron(curses.color_pair(1))
        else:
            win.attron(curses.color_pair(2))
        win.addstr(2, 2, msg[:width-4])
        win.attroff(curses.color_pair(1) if is_error else curses.color_pair(2))
        win.refresh()
        if wait:
            time.sleep(0.5)
        else:
            win.getch()

    def _inline_message(self, msg: str, is_error: bool, wait: bool):
        """Fallback: show message on the main screen."""
        color = curses.color_pair(1) if is_error else curses.color_pair(2)
        self.stdscr.attron(color | curses.A_BOLD)
        self.stdscr.addstr(10, 2, msg[:self.cols-4])
        self.stdscr.attroff(color | curses.A_BOLD)
        if wait:
            time.sleep(0.5)
        else:
            self.stdscr.getch()

    # ---------- Menu Actions ----------
    def analyse(self):
        """Analyse a user‑selected file."""
        path_str = self.prompt_path("Enter file path")
        if not path_str:
            return
        file_path = Path(path_str)
        if not file_path.exists():
            self.show_message("File not found.", is_error=True)
            return
        self.show_message("Analysing...", wait=True)
        try:
            result = analyse_file(file_path, self.config)
            self.current_result = result
            self.report_lines = []
            self.scroll_offset = 0
        except Exception as e:
            self.show_message(f"Error: {e}", is_error=True)

    def select_model(self):
        """Select a new GGUF model."""
        path_str = self.prompt_path("Enter GGUF model path")
        if not path_str:
            return
        model_path = Path(path_str)
        if model_path.exists():
            load_model(str(model_path), self.config)
            if _llama is None:
                self.show_message("Model could not be loaded. See analyser.log.", is_error=True)
                return
            self.config.default_model = str(model_path)
            self.config.save()
            self.show_message(f"Model loaded: {model_path}")
        else:
            self.show_message("Model file not found.", is_error=True)

    def toggle_cache(self):
        """Toggle caching on/off."""
        self.config.cache_enabled = not self.config.cache_enabled
        self.config.save()
        self.show_message(f"Cache {'enabled' if self.config.cache_enabled else 'disabled'}")

    def exit_app(self):
        """Exit the application."""
        self.running = False


# ============================================================================
# ENTRY POINTS
# ============================================================================
def curses_main(stdscr, config):
    """Wrapper to start the curses application."""
    app = CursesApp(stdscr, config)
    app.run()


def main():
    """Application entry point."""
    config = Config.load()
    try:
        wrapper(lambda stdscr: curses_main(stdscr, config))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception("Fatal error")
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()  
