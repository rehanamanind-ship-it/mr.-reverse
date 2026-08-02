# 🔁 Universal Application Converter

**Offline, AI‑powered reverse engineering and code reconstruction**  
Convert any application (`.exe`, `.apk`, `.jar`, `.py`, `.js`, …) into clean source code in your target language – **100% local**, no internet required.
**MADE BY ONLY AND ONLY REHAN AMAN**

---

## 🚀 Features

- **Multi‑format support** – PE (Windows), ELF (Linux), APK, JAR, WASM, Python, JavaScript, and more.
- **Static & dynamic analysis** – extracts imports, strings, sections, and (optionally) runtime API calls.
- **Local AI understanding** – uses a GGUF‑format LLM (CodeLlama, Mistral, etc.) to infer purpose, algorithms, and architecture.
- **AI code generation** – writes complete, modular source code in Python, JavaScript, Java, C++, and others.
- **Offline‑first** – no API keys, no internet – runs entirely on your machine.
- **Compilable** – package into a single native executable with Nuitka for maximum speed.
- **Modular & extensible** – cleanly decoupled components make it easy to add new file types or replace the AI model.

---

## 📦 Installation

```bash
# Clone or download this repository
git clone https://github.com/yourusername/universal-app-converter.git
cd universal-app-converter

# Install Python dependencies (optional, graceful fallbacks)
pip install pefile pyelftools capstone llama-cpp-python


🧠 Download a GGUF Model

Place a .gguf model file in the project directory.
Recommended models (choose one):

    CodeLlama‑7B‑Instruct‑GGUF (choose Q4_K_M for balance)

    Mistral‑7B‑Instruct‑GGUF

🔧 Usage
Basic Command
bash

python converter.py <application_file> --model <model.gguf> --target <language> --output <output_dir>

Examples
bash

# Convert a Windows .exe to Python
python converter.py my_app.exe --model codellama-7b.Q4_K_M.gguf --target python --output ./reconstructed

# Convert a JavaScript app to Python (no AI, heuristic only)
python converter.py app.js --no-ai --output ./reconstructed

# Convert an Android APK to Java
python converter.py my_app.apk --target java --output ./reconstructed


======================================================================
======================================================================



Options
Argument	Description
app	Path to the application file (required).
--target	Target language: python, javascript, java, cpp, etc. (default: python)
--model	Path to the GGUF model file (default: codellama-7b-instruct.Q4_K_M.gguf)
--output	Output directory for generated code (default: ./converted)
--no-ai	Disable AI – use traditional heuristics only.
-v, --verbose	Enable detailed logging.


📂 Output Structure

The converter generates a folder containing:

    Source files – main.py, app.js, Main.java, etc., based on your target language.

    Boilerplate – README.md, requirements.txt, package.json, etc., when applicable.

    All code is fully commented – AI‑generated code includes explanatory comments.

🏗️ Architecture

The tool is built from modular, loosely coupled components:

    FileIdentifier – detects file type and architecture from magic bytes and extensions.

    StaticAnalyzer – extracts imports, exports, strings, sections, and entry points using pluggable backends.

    DynamicAnalyzer – (optional) runs the application in a sandbox and captures system/API calls (currently Linux strace).

    AIAnalyzer – wraps the local LLM (GGUF) to perform behavior analysis and code generation.

    CodeGenerator – facade that chooses between AI‑generated or template‑based code.

    AppConverter – orchestrates the entire pipeline.

Each component can be extended or replaced without affecting the rest – DRY and decoupled by design.


🧪 Requirements

    Python 3.9+

    Optional libraries (but recommended):

        pefile (Windows PE analysis)

        pyelftools (Linux ELF analysis)

        capstone (disassembly)

        llama-cpp-python (local LLM)

    RAM: At least 8 GB (16 GB recommended for 7B models with GPU offload).

    Storage: ~4 GB for the model file.

  

❓ FAQ

Q: Does this work for obfuscated/encrypted binaries?
A: Partially. Obfuscation hinders static analysis – you may need to deobfuscate first. The AI can sometimes infer logic from imported APIs and strings, but results will be less reliable.

Q: Can I use a different GGUF model?
A: Yes – any model compatible with llama-cpp-python will work. Just point --model to your file.

Q: How accurate is the AI‑generated code?
A: The quality depends on the model and the complexity of the original app. For well‑behaved applications, CodeLlama 7B produces readable, working code. Always review and test the output.

Q: Is this legal?
A: Use only on applications you own or have explicit permission to reverse engineer. Respect all applicable laws and license terms.





🌟 Credits

    Built with open‑source tools: llama-cpp-python, pefile, pyelftools, capstone.

    Inspired by the need for offline, privacy‑preserving code recovery. And some things for freedom porposes {use on your on responsiblity}

