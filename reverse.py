#!/usr/bin/env python3
"""
Universal Application Converter – Curses UI Edition
Offline, AI‑powered reverse engineering with a full‑featured terminal interface.

Features:
- Full curses TUI with colors and dynamic resizing
- Scrollable log window
- Real‑time progress updates
- Menu-driven: select input file, target language, model, toggle AI, start conversion
- Threaded conversion engine keeps UI responsive
- Supports all previous analysis and code generation logic
"""

import os
import sys
import re
import json
import subprocess
import tempfile
import shutil
import logging
import threading
import queue
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
import hashlib

# ===================================================================
# Optional imports with graceful fallback (for the engine)
# ===================================================================
try:
    import pefile
except ImportError:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:
    Cs = None

try:
    from llama_cpp import Llama
except ImportError:
    Llama = None

# ===================================================================
# Core Converter Engine – reuses the modular design from previous version
# ===================================================================

@dataclass
class AnalysisResult:
    """Container for all analysis data."""
    file_type: str = ""
    architecture: str = ""
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    sections: List[Dict] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    dynamic_calls: List[str] = field(default_factory=list)
    purpose: str = ""
    algorithms: str = ""
    data_structures: str = ""
    dependencies: List[str] = field(default_factory=list)
    architecture_desc: str = ""
    full_analysis: str = ""
    confidence: float = 0.0


class FileIdentifier:
    """Detects file type and architecture from magic bytes and extension."""
    MAGIC_SIGNATURES = {
        '4d5a': ('PE', 'Windows'),
        '7f454c': ('ELF', 'Linux'),
        '504b0304': ('ZIP', 'Any'),
        'cafebabe': ('JAR', 'Java'),
        '00000020636f': ('WASM', 'WebAssembly'),
        '0a706f': ('Python Bytecode', 'Python'),
    }
    EXT_MAP = {
        '.apk': ('APK', 'Android'),
        '.app': ('Mac App', 'macOS'),
        '.dmg': ('DMG', 'macOS'),
        '.py': ('Python Source', 'Python'),
        '.pyc': ('Python Bytecode', 'Python'),
        '.js': ('JavaScript', 'Web'),
        '.wasm': ('WASM', 'WebAssembly'),
    }

    @classmethod
    def identify(cls, file_path: str) -> Tuple[str, str]:
        if not os.path.exists(file_path):
            return ("Unknown", "Unknown")
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(16).hex()
        except Exception:
            return ("Unknown", "Unknown")
        for sig, (ftype, arch) in cls.MAGIC_SIGNATURES.items():
            if magic.startswith(sig):
                return (ftype, arch)
        ext = Path(file_path).suffix.lower()
        if ext in cls.EXT_MAP:
            return cls.EXT_MAP[ext]
        return ("Unknown", "Unknown")


class StaticAnalyzer:
    """Extracts static information from the file."""
    @classmethod
    def analyze(cls, file_path: str, file_type: str) -> Dict:
        result = {
            'imports': [],
            'exports': [],
            'strings': [],
            'sections': [],
            'entry_points': []
        }
        result['strings'] = cls._extract_strings(file_path, limit=200)
        if file_type == 'PE':
            cls._analyze_pe(file_path, result)
        elif file_type == 'ELF':
            cls._analyze_elf(file_path, result)
        elif file_type in ('Python Source', 'Python Bytecode'):
            cls._analyze_python(file_path, result)
        elif file_type == 'JavaScript':
            cls._analyze_javascript(file_path, result)
        return result

    @staticmethod
    def _extract_strings(file_path: str, limit: int = 200) -> List[str]:
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                matches = re.findall(b'[\\x20-\\x7E]{4,}', data)
                strings = [s.decode('utf-8', errors='ignore') for s in matches[:limit]]
        except Exception:
            pass
        return strings

    @staticmethod
    def _analyze_pe(file_path: str, result: Dict):
        if pefile is None:
            return
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            result['imports'].append(f"{dll}:{imp.name.decode('utf-8', errors='ignore')}")
            for sec in pe.sections:
                result['sections'].append({
                    'name': sec.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'size': sec.SizeOfRawData,
                    'virtual_size': sec.Misc_VirtualSize
                })
            result['entry_points'].append(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        except Exception:
            pass

    @staticmethod
    def _analyze_elf(file_path: str, result: Dict):
        if ELFFile is None:
            return
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    result['sections'].append({
                        'name': section.name,
                        'size': section['sh_size'],
                    })
                if elf.has_dynamic_section():
                    dyn = elf.get_section_by_name('.dynsym')
                    if dyn:
                        for sym in dyn.iter_symbols():
                            if sym.name:
                                result['imports'].append(sym.name)
        except Exception:
            pass

    @staticmethod
    def _analyze_python(file_path: str, result: Dict):
        try:
            if file_path.endswith('.py'):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                try:
                    import ast
                    tree = ast.parse(code)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                result['imports'].append(alias.name)
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                result['imports'].append(node.module)
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _analyze_javascript(file_path: str, result: Dict):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            imports = re.findall(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', code)
            imports += re.findall(r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]', code)
            result['imports'] = list(set(imports))
        except Exception:
            pass


class DynamicAnalyzer:
    """Optional runtime analysis (Linux strace)."""
    @classmethod
    def analyze(cls, file_path: str, file_type: str, timeout: int = 5) -> Dict:
        result = {'calls': []}
        if file_type not in ('PE', 'ELF', 'Python Source', 'JavaScript'):
            return result
        if sys.platform.startswith('linux') and file_type == 'ELF':
            result['calls'] = cls._strace_analysis(file_path, timeout)
        return result

    @staticmethod
    def _strace_analysis(file_path: str, timeout: int) -> List[str]:
        calls = []
        try:
            with tempfile.NamedTemporaryFile(mode='w+') as f:
                cmd = ['strace', '-e', 'trace=file,network,process', '-o', f.name, file_path]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                f.seek(0)
                lines = f.read().splitlines()
                for line in lines[:50]:
                    if any(k in line for k in ('open', 'read', 'write', 'connect', 'send', 'recv')):
                        calls.append(line.strip())
        except Exception:
            pass
        return calls


class AIAnalyzer:
    """Local GGUF model for behavior analysis and code generation."""
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.llm = None
        self._load_model()

    def _load_model(self):
        if Llama is None:
            return
        if not os.path.exists(self.model_path):
            return
        try:
            self.llm = Llama(
                model_path=self.model_path,
                n_ctx=4096,
                n_threads=4,
                n_gpu_layers=-1,
                verbose=False
            )
        except Exception:
            self.llm = None

    def is_available(self) -> bool:
        return self.llm is not None

    def analyze_behavior(self, static: Dict, dynamic: Dict, file_type: str) -> Dict:
        if not self.is_available():
            return self._fallback_analysis(static)

        context = f"""
You are a reverse engineering expert. Analyze the following application based on extracted information.

File type: {file_type}
Imports (first 30): {static.get('imports', [])[:30]}
Exports: {static.get('exports', [])[:20]}
Strings (first 40): {static.get('strings', [])[:40]}
Sections: {static.get('sections', [])}
Dynamic API calls (first 20): {dynamic.get('calls', [])[:20]}

Based on this data, provide a structured analysis in the following format:

Purpose: (one sentence)
Algorithms: (brief description of key algorithms)
Data Structures: (mention any obvious data structures)
Dependencies: (list key external libraries/frameworks)
Architecture: (client-server, MVC, monolithic, etc.)
Confidence: (a number between 0.0 and 1.0 indicating how certain you are)
"""
        try:
            response = self.llm(
                context,
                max_tokens=500,
                temperature=0.2,
                stop=["\n\n"],
                echo=False
            )
            text = response['choices'][0]['text'].strip()
        except Exception:
            return self._fallback_analysis(static)

        parsed = self._parse_ai_response(text)
        parsed['full_analysis'] = text
        return parsed

    def generate_code(self, analysis: Dict, target_lang: str) -> Dict[str, str]:
        if not self.is_available():
            return self._fallback_code_generation(analysis, target_lang)

        prompt = f"""
You are an expert {target_lang} developer. Based on the following application analysis, write a complete, working implementation in {target_lang}.

Analysis:
- Purpose: {analysis.get('purpose', 'Unknown')}
- Algorithms: {analysis.get('algorithms', 'Unknown')}
- Data Structures: {analysis.get('data_structures', 'Unknown')}
- Dependencies: {analysis.get('dependencies', [])}
- Architecture: {analysis.get('architecture_desc', 'Unknown')}

Requirements:
1. Include all necessary imports and dependencies.
2. Implement the core functionality.
3. Use appropriate design patterns.
4. Add error handling and comments.
5. Structure the code into multiple files if needed (e.g., main, modules, classes).
6. Provide the code in a clear, structured format.

Return the code as a single block, but indicate file names with comments like:
# === filename.py ===
"""
        try:
            response = self.llm(
                prompt,
                max_tokens=3000,
                temperature=0.3,
                stop=["\n\n\n"],
                echo=False
            )
            code = response['choices'][0]['text'].strip()
        except Exception:
            return self._fallback_code_generation(analysis, target_lang)

        return self._split_code_into_files(code)

    @staticmethod
    def _parse_ai_response(text: str) -> Dict:
        result = {
            'purpose': '',
            'algorithms': '',
            'data_structures': '',
            'dependencies': [],
            'architecture_desc': '',
            'confidence': 0.5,
            'full_analysis': ''
        }
        purpose_match = re.search(r'Purpose:\s*(.+?)(?=\n|$)', text, re.I)
        if purpose_match:
            result['purpose'] = purpose_match.group(1).strip()
        alg_match = re.search(r'Algorithms:\s*(.+?)(?=\n|$)', text, re.I)
        if alg_match:
            result['algorithms'] = alg_match.group(1).strip()
        ds_match = re.search(r'Data Structures:\s*(.+?)(?=\n|$)', text, re.I)
        if ds_match:
            result['data_structures'] = ds_match.group(1).strip()
        dep_match = re.search(r'Dependencies:\s*(.+?)(?=\n|$)', text, re.I)
        if dep_match:
            deps = [x.strip() for x in dep_match.group(1).split(',') if x.strip()]
            result['dependencies'] = deps
        arch_match = re.search(r'Architecture:\s*(.+?)(?=\n|$)', text, re.I)
        if arch_match:
            result['architecture_desc'] = arch_match.group(1).strip()
        conf_match = re.search(r'Confidence:\s*([0-9.]+)', text)
        if conf_match:
            try:
                result['confidence'] = float(conf_match.group(1))
            except ValueError:
                pass
        return result

    @staticmethod
    def _fallback_analysis(static: Dict) -> Dict:
        imports = static.get('imports', [])
        strings = static.get('strings', [])
        result = {
            'purpose': 'Unknown',
            'algorithms': 'Unknown',
            'data_structures': 'Unknown',
            'dependencies': [imp for imp in imports if '.' in imp or '/' in imp][:10],
            'architecture_desc': 'Unknown',
            'confidence': 0.3,
            'full_analysis': ''
        }
        all_text = ' '.join(imports + strings)
        if any('crypto' in s or 'encrypt' in s or 'decrypt' in s for s in strings):
            result['purpose'] = 'Cryptography/Encryption'
        elif any('socket' in s or 'http' in s or 'url' in s for s in strings):
            result['purpose'] = 'Network/Web communication'
        elif any('sql' in s or 'database' in s or 'db' in s for s in strings):
            result['purpose'] = 'Database management'
        elif any('render' in s or 'graphics' in s or 'shader' in s for s in strings):
            result['purpose'] = 'Graphics/Rendering'
        elif any('game' in s or 'player' in s for s in strings):
            result['purpose'] = 'Game/Entertainment'
        return result

    @staticmethod
    def _fallback_code_generation(analysis: Dict, target_lang: str) -> Dict[str, str]:
        templates = {
            'python': {
                'main.py': '''"""
Reconstructed application from analysis.
Purpose: {purpose}
Generated by traditional method (no AI).
"""
def main():
    print("Application reconstructed (template).")
    # TODO: Implement based on analysis

if __name__ == "__main__":
    main()
''',
                'README.md': '# Reconstructed App\n\nGenerated from binary analysis.',
                'requirements.txt': '# Dependencies inferred'
            },
            'javascript': {
                'app.js': '''/*
Reconstructed application from analysis.
Purpose: {purpose}
*/
console.log("Application reconstructed (template).");
// TODO: Implement based on analysis
''',
                'package.json': '{"name":"reconstructed-app","version":"1.0.0"}',
                'README.md': '# Reconstructed App'
            },
            'java': {
                'Main.java': '''/*
Reconstructed application from analysis.
Purpose: {purpose}
*/
public class Main {
    public static void main(String[] args) {
        System.out.println("Application reconstructed (template).");
    }
}
''',
                'README.md': '# Reconstructed App'
            }
        }
        lang_templates = templates.get(target_lang, templates['python'])
        files = {}
        for fname, content in lang_templates.items():
            files[fname] = content.format(purpose=analysis.get('purpose', 'Unknown'))
        return files

    @staticmethod
    def _split_code_into_files(code: str) -> Dict[str, str]:
        files = {}
        current_file = None
        current_content = []
        for line in code.splitlines():
            marker_match = re.match(r'^\s*[#/]\s*===\s*([^\s]+)\s*===\s*$', line)
            if marker_match:
                if current_file:
                    files[current_file] = '\n'.join(current_content)
                current_file = marker_match.group(1)
                current_content = []
            else:
                current_content.append(line)
        if current_file:
            files[current_file] = '\n'.join(current_content)
        elif current_content:
            main_name = 'main.py'
            if 'javascript' in code.lower():
                main_name = 'app.js'
            elif 'java' in code.lower():
                main_name = 'Main.java'
            files[main_name] = '\n'.join(current_content)
        return files


class ConverterEngine:
    """Orchestrates the conversion pipeline."""
    def __init__(self, model_path: str, use_ai: bool = True):
        self.use_ai = use_ai
        self.ai_analyzer = AIAnalyzer(model_path) if use_ai else None

    def convert(self, app_path: str, target_lang: str, output_dir: str,
                progress_callback: Callable[[str, float], None],
                log_callback: Callable[[str], None]) -> Dict:
        """
        Run the full conversion.
        progress_callback: (stage, percent) where stage is a string and percent 0-100.
        log_callback: (message) for informational logs.
        Returns a dict with analysis, files, metadata.
        """
        def log(msg):
            log_callback(msg)

        def progress(stage, pct):
            progress_callback(stage, pct)

        log("Starting conversion...")
        progress("Initializing", 0)

        # 1. Identify
        file_type, arch = FileIdentifier.identify(app_path)
        log(f"Identified: {file_type} ({arch})")
        progress("Identification", 10)

        # 2. Static
        static = StaticAnalyzer.analyze(app_path, file_type)
        log(f"Static: {len(static['imports'])} imports, {len(static['strings'])} strings")
        progress("Static analysis", 30)

        # 3. Dynamic (optional)
        dynamic = DynamicAnalyzer.analyze(app_path, file_type)
        if dynamic.get('calls'):
            log(f"Dynamic: captured {len(dynamic['calls'])} calls")
        progress("Dynamic analysis", 50)

        # 4. AI understanding
        if self.use_ai and self.ai_analyzer and self.ai_analyzer.is_available():
            log("Running AI behavior analysis...")
            analysis = self.ai_analyzer.analyze_behavior(static, dynamic, file_type)
        else:
            log("Using heuristic analysis (no AI)")
            analysis = self.ai_analyzer._fallback_analysis(static) if self.ai_analyzer else {
                'purpose': 'Unknown',
                'algorithms': 'Unknown',
                'data_structures': 'Unknown',
                'dependencies': [],
                'architecture_desc': 'Unknown',
                'confidence': 0.3,
                'full_analysis': ''
            }
        log(f"Purpose inferred: {analysis.get('purpose', 'Unknown')}")
        progress("AI analysis", 70)

        # 5. Code generation
        log(f"Generating {target_lang} code...")
        if self.use_ai and self.ai_analyzer and self.ai_analyzer.is_available():
            code_files = self.ai_analyzer.generate_code(analysis, target_lang)
        else:
            code_files = self.ai_analyzer._fallback_code_generation(analysis, target_lang) if self.ai_analyzer else {}
        progress("Code generation", 90)

        # 6. Save files
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        for fname, content in code_files.items():
            path = Path(output_dir) / fname
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            log(f"Written: {path}")
        progress("Saving", 100)

        result = {
            'analysis': analysis,
            'files': code_files,
            'metadata': {
                'original_file': app_path,
                'target_language': target_lang,
                'file_type': file_type,
                'architecture': arch,
                'ai_used': self.use_ai and self.ai_analyzer and self.ai_analyzer.is_available(),
                'confidence': analysis.get('confidence', 0.0)
            }
        }
        log("Conversion complete!")
        return result

# ===================================================================
# Curses UI
# ===================================================================

import curses
import curses.textpad

class CursesUI:
    """Full curses TUI for the converter."""
    def __init__(self):
        self.stdscr = None
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.running = True
        self.conversion_thread = None

        # State
        self.app_path = ""
        self.target_lang = "python"
        self.model_path = "codellama-7b-instruct.Q4_K_M.gguf"
        self.use_ai = True
        self.output_dir = "./converted"
        self.conversion_result = None
        self.conversion_in_progress = False
        self.log_lines = []
        self.max_log_lines = 1000
        self.progress_stage = ""
        self.progress_percent = 0

        # Colors (initialized in setup)
        self.color_pairs = {}

    # ------------------- Color Setup -------------------
    def init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        self.color_pairs = {
            'normal': 1,
            'header': 2,
            'highlight': 3,
            'success': 4,
            'error': 5,
            'warning': 6,
            'progress': 7,
        }
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_CYAN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_GREEN, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.init_pair(7, curses.COLOR_BLUE, -1)

    # ------------------- Drawing -------------------
    def draw(self):
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        # Header
        header = " Universal Application Converter - Offline AI "
        self.stdscr.attron(curses.color_pair(self.color_pairs['header']) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, header.ljust(width))
        self.stdscr.attroff(curses.color_pair(self.color_pairs['header']) | curses.A_BOLD)
        self.stdscr.hline(1, 0, curses.ACS_HLINE, width)

        # Main area: split into left (menu) and right (log + progress)
        # We'll use two columns: left 30% for menu, right for log.
        left_width = max(30, int(width * 0.30))
        right_width = width - left_width - 1

        # Left menu
        menu_y = 2
        self.stdscr.attron(curses.color_pair(self.color_pairs['highlight']) | curses.A_BOLD)
        self.stdscr.addstr(menu_y, 0, " SETTINGS ")
        self.stdscr.attroff(curses.color_pair(self.color_pairs['highlight']) | curses.A_BOLD)
        menu_y += 1

        def menu_item(label, value, color='normal'):
            nonlocal menu_y
            if color != 'normal':
                self.stdscr.attron(curses.color_pair(self.color_pairs[color]))
            self.stdscr.addstr(menu_y, 0, f"{label}: ")
            if color != 'normal':
                self.stdscr.attroff(curses.color_pair(self.color_pairs[color]))
            self.stdscr.addstr(menu_y, len(label)+2, f"{value}".ljust(left_width - len(label) - 3))
            menu_y += 1

        # Show settings
        menu_item("App", self.app_path or "(not set)", 'warning' if not self.app_path else 'normal')
        menu_item("Target", self.target_lang)
        menu_item("Model", self.model_path)
        menu_item("AI", "ON" if self.use_ai else "OFF", 'success' if self.use_ai else 'warning')
        menu_item("Output", self.output_dir)

        menu_y += 1
        self.stdscr.addstr(menu_y, 0, " [A] Select App ")
        self.stdscr.addstr(menu_y+1, 0, " [T] Target Language ")
        self.stdscr.addstr(menu_y+2, 0, " [M] Model File ")
        self.stdscr.addstr(menu_y+3, 0, " [I] Toggle AI ")
        self.stdscr.addstr(menu_y+4, 0, " [O] Output Dir ")
        self.stdscr.addstr(menu_y+5, 0, " [S] Start Conversion ")
        self.stdscr.addstr(menu_y+6, 0, " [Q] Quit ")

        # Right side: progress bar and log
        log_x = left_width + 1
        log_y = 2
        log_height = height - 7  # leave room for progress bar

        # Draw a border around log area
        if log_height > 0 and right_width > 10:
            self.stdscr.attron(curses.color_pair(self.color_pairs['normal']))
            self.stdscr.vline(log_y, log_x, curses.ACS_VLINE, log_height)
            self.stdscr.addch(log_y, log_x, curses.ACS_ULCORNER)
            self.stdscr.addch(log_y+log_height-1, log_x, curses.ACS_LLCORNER)
            self.stdscr.addch(log_y, log_x+right_width-1, curses.ACS_URCORNER)
            self.stdscr.addch(log_y+log_height-1, log_x+right_width-1, curses.ACS_LRCORNER)
            self.stdscr.hline(log_y, log_x+1, curses.ACS_HLINE, right_width-2)
            self.stdscr.hline(log_y+log_height-1, log_x+1, curses.ACS_HLINE, right_width-2)
            # log window content
            log_inner = curses.newwin(log_height-2, right_width-2, log_y+1, log_x+1)
            log_inner.attron(curses.color_pair(self.color_pairs['normal']))
            # Show log lines (scrollable)
            start = max(0, len(self.log_lines) - (log_height-2))
            for i, line in enumerate(self.log_lines[start:]):
                if i < log_height-2:
                    try:
                        log_inner.addstr(i, 0, line[:right_width-2])
                    except:
                        pass
            log_inner.refresh()

        # Progress bar at bottom
        prog_y = height - 3
        if self.progress_percent > 0:
            bar_len = right_width - 4
            filled = int(bar_len * self.progress_percent / 100)
            bar = '[' + '#' * filled + '-' * (bar_len - filled) + ']'
            self.stdscr.attron(curses.color_pair(self.color_pairs['progress']) | curses.A_BOLD)
            self.stdscr.addstr(prog_y, log_x+1, f"{self.progress_stage}: {bar} {self.progress_percent}%")
            self.stdscr.attroff(curses.color_pair(self.color_pairs['progress']) | curses.A_BOLD)
        else:
            self.stdscr.addstr(prog_y, log_x+1, "Ready.")

        # Status line
        status_y = height - 1
        status = "Press 'S' to start conversion, 'Q' to quit."
        if self.conversion_in_progress:
            status = "Conversion in progress... please wait."
        self.stdscr.attron(curses.color_pair(self.color_pairs['highlight']))
        self.stdscr.addstr(status_y, 0, status.ljust(width))
        self.stdscr.attroff(curses.color_pair(self.color_pairs['highlight']))

        self.stdscr.refresh()

    # ------------------- Input Handling -------------------
    def handle_input(self, key):
        if key == ord('q') or key == ord('Q'):
            self.running = False
        elif key == ord('s') or key == ord('S'):
            self.start_conversion()
        elif key == ord('a') or key == ord('A'):
            self.prompt_for_app()
        elif key == ord('t') or key == ord('T'):
            self.prompt_for_target()
        elif key == ord('m') or key == ord('M'):
            self.prompt_for_model()
        elif key == ord('i') or key == ord('I'):
            self.use_ai = not self.use_ai
        elif key == ord('o') or key == ord('O'):
            self.prompt_for_output()

    # ------------------- Prompts -------------------
    def prompt_for_app(self):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Enter path to application file: ")
        curses.echo()
        path = self.stdscr.getstr(1, 0, 80).decode('utf-8')
        curses.noecho()
        if os.path.exists(path):
            self.app_path = path
        else:
            self.log_lines.append(f"File not found: {path}")

    def prompt_for_target(self):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Enter target language (python, javascript, java, cpp, etc.): ")
        curses.echo()
        lang = self.stdscr.getstr(1, 0, 20).decode('utf-8').strip()
        curses.noecho()
        if lang:
            self.target_lang = lang

    def prompt_for_model(self):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Enter path to GGUF model file: ")
        curses.echo()
        path = self.stdscr.getstr(1, 0, 120).decode('utf-8')
        curses.noecho()
        if os.path.exists(path):
            self.model_path = path
        else:
            self.log_lines.append(f"Model not found: {path}")

    def prompt_for_output(self):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Enter output directory (default: ./converted): ")
        curses.echo()
        out = self.stdscr.getstr(1, 0, 80).decode('utf-8').strip()
        curses.noecho()
        if out:
            self.output_dir = out

    # ------------------- Conversion Thread -------------------
    def start_conversion(self):
        if self.conversion_in_progress:
            return
        if not self.app_path:
            self.log_lines.append("Please select an application first.")
            return
        if not os.path.exists(self.app_path):
            self.log_lines.append(f"Application not found: {self.app_path}")
            return

        self.conversion_in_progress = True
        self.log_lines = []
        self.progress_stage = ""
        self.progress_percent = 0

        def worker():
            engine = ConverterEngine(self.model_path, self.use_ai)
            try:
                result = engine.convert(
                    self.app_path,
                    self.target_lang,
                    self.output_dir,
                    progress_callback=self.on_progress,
                    log_callback=self.on_log
                )
                self.conversion_result = result
                self.log_lines.append("✅ Conversion finished successfully!")
                self.log_lines.append(f"Output written to: {self.output_dir}")
            except Exception as e:
                self.on_log(f"❌ Conversion failed: {e}")
            finally:
                self.conversion_in_progress = False

        self.conversion_thread = threading.Thread(target=worker, daemon=True)
        self.conversion_thread.start()

    def on_progress(self, stage: str, percent: float):
        self.progress_stage = stage
        self.progress_percent = percent

    def on_log(self, msg: str):
        self.log_lines.append(msg)
        if len(self.log_lines) > self.max_log_lines:
            self.log_lines = self.log_lines[-self.max_log_lines:]

    # ------------------- Main Loop -------------------
    def run(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(0)  # hide cursor
        self.init_colors()

        while self.running:
            self.draw()
            # Check for window resize (KEY_RESIZE)
            try:
                key = self.stdscr.getch()
            except KeyboardInterrupt:
                break
            if key == curses.KEY_RESIZE:
                continue
            if key != -1:
                self.handle_input(key)

            # Process any pending log/progress messages (already handled via callbacks)
            # The callbacks directly update the log_lines and progress variables.
            time.sleep(0.1)  # small delay to reduce CPU

        # Cleanup
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Goodbye!")
        self.stdscr.refresh()
        time.sleep(1)

# ===================================================================
# Entry point
# ===================================================================

def main():
    ui = CursesUI()
    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    print("Exited.")

if __name__ == "__main__":
    main()
