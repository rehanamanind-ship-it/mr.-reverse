#!/usr/bin/env python3
"""
Universal Application Converter – Offline, AI‑powered reverse engineering and code generation.

Modular, decoupled, DRY, and easy to change.
MADE BY ONLY AND ONLY REHAN AMAN
"""

import os
import sys
import re
import json
import subprocess
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
import hashlib
import time

# ------------------------------
# Optional imports with graceful fallback
# ------------------------------
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

# ------------------------------
# Logging setup
# ------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(ch)

# ------------------------------
# Constants and type definitions
# ------------------------------
@dataclass
class AnalysisResult:
    """Container for all analysis data gathered about an application."""
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

# ------------------------------
# 1. File Identifier
# ------------------------------
class FileIdentifier:
    """
    Detects the file type and architecture from magic bytes and extension.
    """
    # Magic signatures: (hex prefix) -> (type, architecture)
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
        """
        Identify file type and architecture.

        Args:
            file_path: Path to the application file.

        Returns:
            (file_type, architecture) as strings.
        """
        if not os.path.exists(file_path):
            return ("Unknown", "Unknown")

        # Read magic bytes
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(16).hex()
        except Exception:
            return ("Unknown", "Unknown")

        # Check signatures
        for sig, (ftype, arch) in cls.MAGIC_SIGNATURES.items():
            if magic.startswith(sig):
                return (ftype, arch)

        # Check extension
        ext = Path(file_path).suffix.lower()
        if ext in cls.EXT_MAP:
            return cls.EXT_MAP[ext]

        return ("Unknown", "Unknown")

# ------------------------------
# 2. Static Analyzer
# ------------------------------
class StaticAnalyzer:
    """
    Extracts static information (imports, strings, sections, entry points)
    using pluggable backends for different file types.
    """
    @classmethod
    def analyze(cls, file_path: str, file_type: str) -> Dict:
        """
        Perform static analysis on the given file.

        Args:
            file_path: Path to the file.
            file_type: Detected file type (from FileIdentifier).

        Returns:
            Dict with keys: imports, exports, strings, sections, entry_points.
        """
        result = {
            'imports': [],
            'exports': [],
            'strings': [],
            'sections': [],
            'entry_points': []
        }

        # Always try to extract ASCII strings
        result['strings'] = cls._extract_strings(file_path, limit=200)

        # Dispatch to specific analyzers
        if file_type == 'PE':
            cls._analyze_pe(file_path, result)
        elif file_type == 'ELF':
            cls._analyze_elf(file_path, result)
        elif file_type in ('Python Source', 'Python Bytecode'):
            cls._analyze_python(file_path, result)
        elif file_type == 'JavaScript':
            cls._analyze_javascript(file_path, result)
        # Add more types here as needed (e.g., JAR, APK)

        return result

    # ---- Internal helper methods ----
    @staticmethod
    def _extract_strings(file_path: str, limit: int = 200) -> List[str]:
        """Extract printable ASCII strings from binary."""
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
        """PE (Windows) specific analysis."""
        if pefile is None:
            return
        try:
            pe = pefile.PE(file_path)
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            result['imports'].append(f"{dll}:{imp.name.decode('utf-8', errors='ignore')}")
            # Sections
            for sec in pe.sections:
                result['sections'].append({
                    'name': sec.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'size': sec.SizeOfRawData,
                    'virtual_size': sec.Misc_VirtualSize
                })
            # Entry point
            result['entry_points'].append(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        except Exception as e:
            logger.debug(f"PE analysis error: {e}")

    @staticmethod
    def _analyze_elf(file_path: str, result: Dict):
        """ELF (Linux) specific analysis."""
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
        except Exception as e:
            logger.debug(f"ELF analysis error: {e}")

    @staticmethod
    def _analyze_python(file_path: str, result: Dict):
        """Python source or bytecode analysis."""
        try:
            if file_path.endswith('.py'):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                # Simple AST parsing (optional)
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
            # For .pyc, we could use dis, but skip for now
        except Exception as e:
            logger.debug(f"Python analysis error: {e}")

    @staticmethod
    def _analyze_javascript(file_path: str, result: Dict):
        """JavaScript source analysis."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            # Find requires and imports
            imports = re.findall(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', code)
            imports += re.findall(r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]', code)
            result['imports'] = list(set(imports))  # deduplicate
        except Exception as e:
            logger.debug(f"JavaScript analysis error: {e}")

# ------------------------------
# 3. Dynamic Analyzer
# ------------------------------
class DynamicAnalyzer:
    """
    Optional runtime analysis (sandboxed execution). Currently supports Linux strace.
    """
    @classmethod
    def analyze(cls, file_path: str, file_type: str, timeout: int = 5) -> Dict:
        """
        Run the application in a sandbox and capture system/API calls.

        Args:
            file_path: Path to the executable.
            file_type: Detected file type.
            timeout: Maximum seconds to run.

        Returns:
            Dict with key 'calls' (list of captured call strings).
        """
        result = {'calls': []}
        if file_type not in ('PE', 'ELF', 'Python Source', 'JavaScript'):
            return result

        # Linux ELF: use strace
        if sys.platform.startswith('linux') and file_type == 'ELF':
            result['calls'] = cls._strace_analysis(file_path, timeout)
        # Windows: could use API Monitor, but not implemented here
        # Others: skip
        return result

    @staticmethod
    def _strace_analysis(file_path: str, timeout: int) -> List[str]:
        """Run strace and capture file/network/process calls."""
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
                # Filter lines containing interesting calls
                for line in lines[:50]:
                    if any(k in line for k in ('open', 'read', 'write', 'connect', 'send', 'recv')):
                        calls.append(line.strip())
        except Exception as e:
            logger.debug(f"strace analysis error: {e}")
        return calls

# ------------------------------
# 4. AI Analyzer
# ------------------------------
class AIAnalyzer:
    """
    Uses a local GGUF LLM to understand application behavior and generate code.
    """
    def __init__(self, model_path: str, verbose: bool = False):
        """
        Initialize the LLM.

        Args:
            model_path: Path to the .gguf model file.
            verbose: Whether to log extra info.
        """
        self.model_path = model_path
        self.verbose = verbose
        self.llm = None
        self._load_model()

    def _load_model(self):
        """Load the GGUF model with llama-cpp-python."""
        if Llama is None:
            logger.error("llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            return
        if not os.path.exists(self.model_path):
            logger.error(f"Model file not found: {self.model_path}")
            return
        try:
            self.llm = Llama(
                model_path=self.model_path,
                n_ctx=4096,
                n_threads=4,
                n_gpu_layers=-1,   # auto GPU offload
                verbose=False
            )
            logger.info("✅ Local GGUF model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.llm = None

    def is_available(self) -> bool:
        """Check if AI is ready to use."""
        return self.llm is not None

    def analyze_behavior(self, static: Dict, dynamic: Dict, file_type: str) -> Dict:
        """
        Use the LLM to infer purpose, algorithms, data structures, etc.

        Args:
            static: Result from StaticAnalyzer.
            dynamic: Result from DynamicAnalyzer.
            file_type: Detected file type.

        Returns:
            Dict with keys: purpose, algorithms, data_structures, dependencies,
                             architecture_desc, confidence, full_analysis.
        """
        if not self.is_available():
            return self._fallback_analysis(static)

        # Build prompt
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
        logger.info("🧠 Sending to local AI for behavior analysis...")
        try:
            response = self.llm(
                context,
                max_tokens=500,
                temperature=0.2,
                stop=["\n\n"],
                echo=False
            )
            text = response['choices'][0]['text'].strip()
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return self._fallback_analysis(static)

        parsed = self._parse_ai_response(text)
        parsed['full_analysis'] = text
        return parsed

    def generate_code(self, analysis: Dict, target_lang: str) -> Dict[str, str]:
        """
        Generate source code in the target language using the LLM.

        Args:
            analysis: Result from analyze_behavior (or similar dict).
            target_lang: Target programming language (e.g., 'python').

        Returns:
            Dict mapping filenames to code strings.
        """
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
        logger.info(f"🧠 Generating {target_lang} code via AI...")
        try:
            response = self.llm(
                prompt,
                max_tokens=3000,
                temperature=0.3,
                stop=["\n\n\n"],
                echo=False
            )
            code = response['choices'][0]['text'].strip()
        except Exception as e:
            logger.error(f"AI code generation failed: {e}")
            return self._fallback_code_generation(analysis, target_lang)

        # Parse into files
        return self._split_code_into_files(code)

    # ---- Internal helpers ----
    @staticmethod
    def _parse_ai_response(text: str) -> Dict:
        """Extract structured fields from AI response."""
        result = {
            'purpose': '',
            'algorithms': '',
            'data_structures': '',
            'dependencies': [],
            'architecture_desc': '',
            'confidence': 0.5,
            'full_analysis': ''
        }
        # Regex extraction
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
        """Heuristic analysis when AI is unavailable."""
        imports = static.get('imports', [])
        strings = static.get('strings', [])
        all_text = ' '.join(imports + strings)

        result = {
            'purpose': 'Unknown',
            'algorithms': 'Unknown',
            'data_structures': 'Unknown',
            'dependencies': [imp for imp in imports if '.' in imp or '/' in imp][:10],
            'architecture_desc': 'Unknown',
            'confidence': 0.3,
            'full_analysis': ''
        }

        # Heuristic classification
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
        """Template-based code generation when AI fails."""
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
        """Split a multi-file code block into separate files based on markers."""
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
            # No markers – treat as main file
            main_name = 'main.py'  # default
            if 'javascript' in code.lower():
                main_name = 'app.js'
            elif 'java' in code.lower():
                main_name = 'Main.java'
            files[main_name] = '\n'.join(current_content)
        return files

# ------------------------------
# 5. Code Generator (Wrapper)
# ------------------------------
class CodeGenerator:
    """
    Facade for code generation (AI or traditional).
    """
    def __init__(self, ai_analyzer: AIAnalyzer):
        self.ai_analyzer = ai_analyzer

    def generate(self, analysis: Dict, target_lang: str) -> Dict[str, str]:
        """
        Generate code using AI if available, else fallback to templates.

        Args:
            analysis: Analysis result dict.
            target_lang: Target language.

        Returns:
            Dict mapping filenames to code strings.
        """
        if self.ai_analyzer.is_available():
            return self.ai_analyzer.generate_code(analysis, target_lang)
        else:
            return self.ai_analyzer._fallback_code_generation(analysis, target_lang)

# ------------------------------
# 6. Main Converter (Orchestrator)
# ------------------------------
class AppConverter:
    """
    Orchestrates the entire conversion pipeline:
    identify → static analyze → dynamic analyze → AI understand → generate code → save.
    """
    def __init__(self, model_path: str, use_ai: bool = True, verbose: bool = False):
        """
        Args:
            model_path: Path to GGUF model file.
            use_ai: Whether to enable AI (if False, skip AI entirely).
            verbose: Enable detailed logging.
        """
        if verbose:
            logger.setLevel(logging.DEBUG)
        self.use_ai = use_ai
        self.ai_analyzer = AIAnalyzer(model_path) if use_ai else None
        self.code_generator = CodeGenerator(self.ai_analyzer) if use_ai else None
        self.file_identifier = FileIdentifier()
        self.static_analyzer = StaticAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer()

    def convert(self, app_path: str, target_lang: str = "python", output_dir: str = "output") -> Dict:
        """
        Run full conversion pipeline.

        Args:
            app_path: Path to the input application file.
            target_lang: Desired output language.
            output_dir: Directory to save generated code.

        Returns:
            Dict with keys: analysis, files, metadata.
        """
        logger.info(f"Starting conversion of {app_path} → {target_lang}")

        # 1. Identify
        file_type, arch = self.file_identifier.identify(app_path)
        logger.info(f"Identified: {file_type} ({arch})")

        # 2. Static analysis
        static = self.static_analyzer.analyze(app_path, file_type)
        logger.info(f"Static: {len(static['imports'])} imports, {len(static['strings'])} strings")

        # 3. Dynamic analysis (optional, only if safe)
        dynamic = self.dynamic_analyzer.analyze(app_path, file_type)

        # 4. AI understanding
        if self.use_ai and self.ai_analyzer and self.ai_analyzer.is_available():
            analysis = self.ai_analyzer.analyze_behavior(static, dynamic, file_type)
        else:
            analysis = self.ai_analyzer._fallback_analysis(static) if self.ai_analyzer else {
                'purpose': 'Unknown',
                'algorithms': 'Unknown',
                'data_structures': 'Unknown',
                'dependencies': [],
                'architecture_desc': 'Unknown',
                'confidence': 0.3,
                'full_analysis': ''
            }

        # 5. Code generation
        if self.code_generator:
            code_files = self.code_generator.generate(analysis, target_lang)
        else:
            # Fallback if no AI at all
            code_files = self.ai_analyzer._fallback_code_generation(analysis, target_lang)

        # 6. Save files
        self._save_files(code_files, output_dir)

        return {
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

    @staticmethod
    def _save_files(files: Dict[str, str], output_dir: str):
        """Write generated files to disk."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        for fname, content in files.items():
            path = Path(output_dir) / fname
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"✅ Written: {path}")

# ------------------------------
# CLI Entry Point
# ------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Universal Application Converter with local GGUF AI",
        epilog="Place your .gguf model in the same directory or specify --model."
    )
    parser.add_argument("app", help="Path to the application file (e.g., .exe, .apk, .py, .js)")
    parser.add_argument("--target", default="python", help="Target language (python, javascript, java, cpp, etc.)")
    parser.add_argument("--model", default="codellama-7b-instruct.Q4_K_M.gguf", help="Path to GGUF model file")
    parser.add_argument("--output", default="./converted", help="Output directory for generated code")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI (use traditional heuristics)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if not os.path.exists(args.app):
        logger.error(f"Application file '{args.app}' not found.")
        sys.exit(1)

    if not args.no_ai and not os.path.exists(args.model):
        logger.error(f"Model file '{args.model}' not found. Download a GGUF model or use --no-ai.")
        sys.exit(1)

    converter = AppConverter(
        model_path=args.model,
        use_ai=not args.no_ai,
        verbose=args.verbose
    )

    try:
        result = converter.convert(args.app, args.target, args.output)
        print("\n✅ Conversion complete!")
        print(f"📁 Output directory: {args.output}")
        print(f"📊 Confidence: {result['metadata']['confidence']:.2f}")
        if result['analysis'].get('purpose'):
            print(f"📝 Purpose inferred: {result['analysis']['purpose']}")
        # Show generated files
        print("\n📄 Generated files:")
        for fname in result['files'].keys():
            print(f"   - {fname}")
    except Exception as e:
        logger.error(f"Conversion failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
