
That's the vibe. Plain text, indented, color only when it helps, TTY-aware.

### 1.2 What HREA Is NOT
- ❌ Not a full‑screen TUI (no Textual, no curses, no Urwid)
- ❌ Not interactive – no REPL, no keyboard navigation, no scrolling panels
- ❌ Not Rich, not `colorama` fireworks, not spinner libraries
- ❌ Not like `htop` / `btop` / `lazygit` / `k9s`
- ❌ Not piping through `jq`-style pretty JSON by default

### 1.3 What HREA IS
- ✅ A **subcommand CLI** – `hrea <command> [args]`
- ✅ **Scriptable** – works in shell scripts, Makefiles, CI pipelines
- ✅ **Pipeable** – plain text out, `--json` for structured data
- ✅ **TTY‑aware** – colors only when stdout is a terminal
- ✅ **Ships as `.whl`** – `pip install hrea.whl` → `hrea` command just works
- ✅ **Zero UI dependencies** – only `argparse` or `click` for parsing

### 1.4 Libraries
**Just one:** the CLI framework. Pick **one** of these (prefer the first):

1. **`argparse`** (stdlib) – if the tool stays small
2. **`click`** – if you need nested subcommands and rich help
3. **`typer`** – only if you already prefer it; it wraps `click`

**Do NOT add `rich`, `halo`, `tqdm`, `colorama`, `blessed`, `urwid`, or any TUI/pretty‑print library.**  
For color, use raw ANSI escape codes guarded by `sys.stdout.isatty()`. That's what `git` does.

### 1.5 Command Structure

hrea # top-level command
├── convert Convert an application to source code
├── analyze Analyze an application without generating code
├── detect Detect file type, architecture, and packer
├── list-tools Show available decompilers and AI models
├── doctor Diagnose environment and dependencies
├── config Manage configuration (models path, defaults)
└── version Show version and build info
text


### 1.6 Required Flags
Every subcommand must support:

| Flag | Purpose |
|------|---------|
| `--target, -t` | Target language (`python`, `js`, `java`, `cpp`, …) |
| `--model, -m` | Path to a GGUF model file |
| `--output, -o` | Output directory |
| `--no-ai` | Disable AI, use heuristics only |
| `--json` | Machine‑readable JSON output (for scripting / CI) |
| `--quiet, -q` | Only print errors |
| `--verbose, -v` | Print extra diagnostic lines |
| `--no-color` | Disable ANSI colors (auto‑off when piped) |
| `--yes, -y` | Skip confirmation prompts |

### 1.7 Output Style

- **Plain text lines**, one fact per line.
- **Left‑aligned labels** followed by values, like `git` and `cargo`.
- **Indent with two spaces** for sub‑items.
- **Colors only when `isatty()`** – red for errors, yellow for warnings, green for success, cyan for stage labels.
- **No emoji** unless the user explicitly opts in via `--emoji` (off by default).
- **No spinners** – instead print a single line per stage: `[stage] message`.
- **No animated progress bars** – print `[stage] message (n/total)` occasionally, or nothing.
- **No tables** – use fixed‑width padding and plain columns.
- **Exit codes** – `0` success, `1` user error, `2` internal error.
- **`--json` mode** – prints exactly one JSON object to stdout, nothing else. Ever.

### 1.8 Example UX (Reference)

```bash
$ hrea analyze ./my_app.exe
Reading binary... done (0.42s)
Detecting file type... PE / x86_64
Extracting static data... 128 imports, 342 strings
Running dynamic analysis... 12 syscalls captured
Querying local AI model... done

File type:       PE (Windows)
Architecture:    x86_64
Packer:          none detected
Purpose:         Scientific calculator
Algorithms:      basic arithmetic, trig, log
Dependencies:    kernel32, user32, msvcrt
Confidence:      0.78

Analysis complete.

bash

$ hrea convert ./my_app.exe -t python -o ./out --model ./codellama.gguf
Identifying binary... PE / x86_64
Static analysis... 128 imports, 342 strings
Dynamic analysis... 12 syscalls captured
AI behavior analysis... done
Generating python code... done
Writing files... done

Generated files in ./out:
  main.py
  calculator.py
  memory.py
  utils.py
  README.md

Conversion complete in 14.2s.

bash

$ hrea analyze ./my_app.exe --json
{"file_type":"PE","architecture":"x86_64","packer":null,"purpose":"Scientific calculator","confidence":0.78}

$ hrea analyze ./my_app.exe --json | jq -r .purpose
Scientific calculator

bash

$ hrea doctor
Checking environment...

Python:              3.11.5    ok
llama-cpp-python:    0.2.79    ok
pefile:              2023.2.7  ok
pyelftools:          0.29      ok
capstone:            5.0.0     ok
ghidra (headless):   not found
radare2:             not found
capstone (fallback): ok

2 tools missing but at least one decompiler backend is available.
Environment is usable.

1.9 Configuration

    Config file at ~/.config/hrea/config.toml (Linux/macOS) or %APPDATA%\hrea\config.toml (Windows).

    Managed via hrea config set/get/list.

    CLI flags always override config file values.

    Environment variables supported (HREA_MODEL_PATH, HREA_OUTPUT_DIR, etc.).

1.10 Instructions for the AI Coder (CLI)

    Do not use curses, Textual, Rich, or any TUI/pretty‑print library.

    Use argparse (stdlib) by default, or click if nested subcommands get painful.

    Write plain print() statements – one fact per line.

    Color via raw ANSI codes, only when sys.stdout.isatty() is True. Provide --no-color to force off.

    Support --json on every command that produces data. In JSON mode, suppress all other output.

    Never block – wrap long tasks with try/except KeyboardInterrupt and exit cleanly with code 130.

    Exit codes must be meaningful – 0 success, 1 user error, 2 internal error.

    Only dependency added to pyproject.toml for the CLI layer: click>=8.1 (or nothing if using argparse).

    Add a --version flag and a version subcommand.

    Test on Windows Terminal, iTerm2, Kitty, Alacritty, and plain bash – verify output is clean when piped.

📦 2. Packaging – Ship as a .whl Wheel

    PRIORITY #1 – the final deliverable must be a PEP 517/518‑compliant Python wheel that installs with a single command.

2.1 Goal

Users must be able to install the tool with:
bash

pip install hrea-1.0.0-py3-none-any.whl

…and immediately use it as hrea on the command line – no cloning, no manual pip install -r requirements.txt.
2.2 Required Packaging Setup

The AI coder must create:

    pyproject.toml – modern build configuration using setuptools as the backend.

    Console entry point – hrea = "src.main:main".

    README.md – rendered on PyPI and included in the wheel metadata.

    LICENSE – required for distribution.

    MANIFEST.in – include non‑Python assets.

    Version pinning – all runtime dependencies pinned to compatible ranges.

2.3 Example pyproject.toml
toml

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "hrea"
version = "1.0.0"
description = "Heuravox Reverse Engineer Anything – offline AI-powered universal application converter"
readme = "README.md"
requires-python = ">=3.9"
license = { file = "LICENSE" }
authors = [{ name = "Rehan Aman" }]
keywords = ["reverse-engineering", "decompiler", "ai", "gguf", "offline"]
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Topic :: Software Development :: Disassemblers",
]

dependencies = [
    "click>=8.1",
    "pefile>=2023.2.7",
    "pyelftools>=0.29",
    "capstone>=5.0.0",
    "llama-cpp-python>=0.2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "ruff>=0.4.0",
    "mypy>=1.8",
    "build>=1.0",
]

[project.scripts]
hrea = "src.main:main"


[tool.setuptools]
packages = ["src"]
include-package-data = true

[tool.setuptools.package-data]
src = ["*.toml", "*.json"]

2.4 Build Instructions
bash

pip install build
python -m build
# Output:
#   dist/hrea-1.0.0-py3-none-any.whl
#   dist/hrea-1.0.0.tar.gz

2.5 Verification Steps (Must Be Included)
bash

python -m venv /tmp/testenv
source /tmp/testenv/bin/activate
pip install dist/hrea-1.0.0-py3-none-any.whl
hrea --version
hrea --help
hrea analyze ./tests/fixtures/sample.py --no-ai

2.6 Platform Wheels (Optional but Recommended)

    Pure Python wheel (py3-none-any.whl) – works everywhere but requires user to have llama-cpp-python preinstalled.

    Platform‑specific wheels – if bundling llama-cpp-python, build per platform.

    Use cibuildwheel for automation if needed.

2.7 Instructions for the AI Coder (Packaging)

    Create pyproject.toml with the structure shown in §2.3.

    Ensure the entry point hrea = "src.main:main" works after installation.

    Pin dependencies with sensible version ranges.

    Include README.md and LICENSE in the wheel metadata.

    Automate the build – add a Makefile or build.sh / build.ps1 target.

    Add a CI step (GitHub Actions) that builds the wheel on every tag.

    Test the wheel in a clean venv before declaring a release ready.

    Document installation in README.md.

🧠 3. AI & Cognitive Limitations
3.1 Logic Hallucinations

Problem: AI guesses how a function works and writes flawed code based on false assumptions.

Instructions to the AI coder (add these features):

    Confidence scoring – every AI‑generated function gets a confidence value. If < 0.6, print a warning line: warning: low confidence in function_name (0.42).

    Multi‑hypothesis generation – for ambiguous functions, ask the AI for 2–3 candidate implementations. Pick the best one using a heuristic scorer.

    Cross‑validation loop – after generating code, re‑run the static analyzer on the output and compare imports/strings with the original. If mismatch > 30%, discard and retry (max 3 attempts).

    Human‑in‑the‑loop mode – via --interactive flag, present hypotheses as a numbered list and let the user pick.

3.2 Architectural Blindness

Problem: AI fails to understand global application state, multi‑threading, or async loops.

Instructions to the AI coder (add these features):

    Global state graph extraction – parse the binary for global variables, thread creation, and sync primitives. Feed this graph to the AI as extra context.

    Concurrency‑aware prompts – detect async patterns and instruct the AI to preserve the concurrency model.

    Top‑down architecture pass – before generating any code, ask the AI to describe the overall architecture and store it as architecture_desc.

    Thread/async listing – print the detected threads and async flows as plain indented lines in verbose mode.

3.3 Literal‑to‑Functional Translation Errors

Problem: AI struggles to convert ugly decompiled pseudo‑code (v1, v2, v3) into clean, idiomatic code.

Instructions to the AI coder (add these features):

    Variable renaming heuristics before feeding code to the AI.

    AI‑powered naming – ask the AI to suggest meaningful names for variables and functions based on context.

    Post‑processing beautification – run black (Python), prettier (JS), clang-format (C++), google-java-format (Java) on the output.

    Idiom mapping – maintain a small table of common decompiled patterns → idiomatic equivalents.

⚙️ 4. Technical & Tooling Failures
4.1 Brittle External Dependencies

Problem: Tool breaks if third‑party decompilers (Ghidra, IDA, Hopper) are missing or misconfigured.

Instructions to the AI coder:

    Pluggable decompiler backends with a common interface:
    python

    class DecompilerBackend(ABC):
        @abstractmethod
        def decompile(self, binary_path: str) -> str: ...
        @abstractmethod
        def is_available(self) -> bool: ...

    Support: Ghidra (headless), RetDec, Radare2, Capstone (fallback).

    Auto‑detection at startup – pick the first available backend, list it via hrea list-tools.

    Bundle Capstone as a zero‑dependency fallback.

    Graceful degradation – if no decompiler works, produce a high‑level analysis and template code.

4.2 Automation Script Failures

Problem: AI‑generated commands for decompilers are invalid, stalling the pipeline.

Instructions to the AI coder:

    Command whitelist validation before execution.

    Retry with feedback – send the error back to the AI and request a corrected version (max 3 retries).

    Sandboxed execution – subprocess with timeout, capture stdout/stderr.

    Pre‑written, tested scripts – ship tested scripts for common decompilers.

4.3 Environment Drift

Problem: OS, shell, or tool updates break brittle automation hooks.

Instructions to the AI coder:

    Platform adapters – LinuxAdapter, WindowsAdapter, MacAdapter.

    Use platform and subprocess with explicit paths – never rely on shell aliases.

    Version checks for external tools; warn on incompatibility.

    hrea doctor command – prints a plain checklist of tools and their status.

4.4 Dynamic Analysis Hard Blockers

Problem: Apps relying on runtime state, server‑side validation, or hidden IPC.

Instructions to the AI coder:

    API hooking via Frida to intercept IPC, network calls, and syscalls.

    Server‑side simulation – record network requests, replay with mock responses.

    Symbolic execution (via angr) for small critical functions.

    IPC detection – pipes, shared memory, sockets – log and print in verbose mode.

🛡️ 5. Obfuscation & Security Defenses
5.1 Symbol Stripping Failures

Instructions to the AI coder:

    FLIRT signatures to identify known library functions.

    String‑reference matching – infer function purpose from nearby string constants.

    AI‑based name suggestion – feed opcode sequences to the local model.

    Symbol database – ship a curated DB of common libc / OpenSSL / zlib functions.

    Few‑shot prompting with the local model.

5.2 Packer & Crypter Inability

Instructions to the AI coder:

    Entropy analysis + signature matching to detect packers.

    Dynamic unpacking – run in a sandbox, dump memory after the unpacking stub completes.

    Integration with unipacker / packerid.

    Behavioral fallback – observe runtime behavior and generate code from that.

5.3 Anti‑Debugging Defeat

Instructions to the AI coder:

    Anti‑anti‑debugging patches for common checks.

    Hypervisor‑based debugging (KVM / Xen) for stealth.

    Timing/breakpoint randomization.

    Emulated environment (QEMU) to avoid host interaction.

    Auto‑restart with different evasion settings.

5.4 Control‑Flow Flattening

Instructions to the AI coder:

    CFG reconstruction using Capstone / Radare2.

    De‑flattening algorithms (pattern‑based + symbolic execution).

    Feed the de‑flattened CFG to the AI instead of raw disassembly.

    Dynamic tracing fallback – record actual execution paths.

🧪 6. Testing Strategy

    Every feature must be tested. No exceptions.

6.1 Testing Rules for AI Coders

    Use pytest – no other framework.

    Mock the LLM in all tests – never load a real GGUF during CI.

    Use click.testing.CliRunner (or subprocess) for CLI tests.

    Fixtures in conftest.py – sample binaries, mock AI responses, temp output dirs.

    Coverage target: 80%+.

    No network calls in tests.

    Every bug fix gets a regression test.

    Tests must run in < 30 seconds.

6.2 Test Categories
Category	What it covers	Example
Unit	Single function / class in isolation	FileIdentifier.identify() on a fake magic header
Integration	Two or more components together	ConverterEngine with mocked AI
CLI	Subcommands and flags	Invoke hrea analyze --json and assert output
Regression	Previously fixed bugs	A binary that used to crash the parser
Performance	Runtime ceilings	Conversion of a 10 MB binary completes in < 60s
Packaging	Wheel integrity	pip install dist/*.whl in a clean venv, then run hrea --version
6.3 Fixtures to Provide

    sample.exe – tiny PE binary (or synthetic)

    sample.elf – tiny ELF binary

    sample.py – Python source sample

    mock_responses.json – canned AI responses

🚫 7. Out of Scope (Do NOT Waste Effort Here)

    Context Window Exhaustion – We use local GGUF models. Their context limits are accepted.

    Docker distribution – not required. The .whl wheel is the only distribution target.

    Full‑screen TUI (Textual, curses, Urwid) – explicitly rejected.

    Rich / pretty‑print libraries – explicitly rejected. Plain print() + optional ANSI only.

✅ 8. General Instructions for AI Coders

When working on this project, always:

    Follow DRY, decoupling, and readability principles.

    Add docstrings to every function and class.

    Write unit tests for each new component.

    Use type hints everywhere.

    Prefer composition over inheritance.

    Keep functions small (≤ 50 lines).

    Log extensively using Python's logging module – never print debug info in library code.

    Handle exceptions gracefully – never crash the whole pipeline.

    Cache expensive operations (AI calls, disassembly) using functools.lru_cache or a disk cache.

    Make everything configurable via config file + CLI flags.

    Reference this file in code comments: # See models.md §3.1 where relevant.

    Do not introduce new external dependencies without updating pyproject.toml and justifying the addition.

    Keep source code to a minimum number of files – do not over‑split.

    Never block the CLI – wrap long tasks and handle Ctrl+C.

    Every PR must include tests – no feature is complete without them.

    Every release must produce a working .whl – verified in a clean venv.

📅 9. Roadmap (Priority Order)
Priority	Task	Section
🔴 P0	Implement minimal Git‑style CLI (argparse or click)	§1
🔴 P0	Package as .whl with pyproject.toml	§2
🔴 P0	Set up tests/ folder with pytest + fixtures	§6
🔴 P0	Mock LLM in all tests	§6.1
🟠 P1	Pluggable decompiler backends (Capstone fallback)	§4.1
🟠 P1	Confidence scoring + multi‑hypothesis AI	§3.1
🟠 P1	Global state / thread graph extraction	§3.2
🟠 P1	Command whitelist + retry for decompiler scripts	§4.2
🟠 P1	hrea doctor diagnostic command	§4.3
🟡 P2	Variable renaming heuristics + beautification	§3.3
🟡 P2	Symbol recovery (FLIRT + AI)	§5.1
🟡 P2	Anti‑anti‑debugging	§5.3
🟡 P2	Platform adapters for env drift	§4.3
🟢 P3	Automatic unpacking	§5.2
🟢 P3	Control‑flow de‑flattening	§5.4
🟢 P3	API hooking with Frida	§4.4
📖 10. How to Use This File
If you are an AI coding assistant:

    Read this entire file before making any changes.

    Start with P0 tasks (§9). Do not skip ahead.

    For each task, read the corresponding section (§0–§6).

    Implement the mitigation following the specific instructions.

    Add tests for everything you build.

    Update the code with comments referencing the section (e.g., # See models.md §1.4).

    Run the full test suite (pytest) and build the wheel (python -m build) before finishing.

    Verify the wheel in a clean venv (pip install dist/*.whl && hrea --version).

    Document changes in the commit message.

If you are a human developer:

    Use this as a checklist when reviewing AI‑generated code.

    Ensure all P0 and P1 mitigations are implemented before calling a release "stable."

    Update this file whenever new limitations or requirements are discovered.

Project: Heuravox Reverse Engineer Anything (HREA)
Command: hrea
Positioning: Professional, offline, local alternative to rea – fixing its known failure modes (§3–§5).
Last updated: 2025
Maintainer: Project Owner
Status: Living document – subject to change