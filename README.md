# HREA

HREA is a lightweight reverse-engineering and conversion CLI designed to detect binary characteristics, analyze file intent, and generate placeholder conversion output for a target language.

## Installation

```bash
pip install hrea-1.0.0-py3-none-any.whl
```

After installation, the CLI is available as:

```bash
hrea --help
```

## Features

- Analyze a file for type, architecture, packer, and purpose
- Detect script/binary metadata
- Convert a target binary into a scaffolded source file
- Read and write configuration values with `hrea config`
- Run environment checks with `hrea doctor`

## Commands

```bash
hrea analyze ./example.exe --json
hrea detect ./example.exe
hrea convert ./example.exe -t python -o ./out --json
hrea doctor
hrea config set default_target js
```

## Notes

This project is intentionally dependency-light and stdout-friendly for scripting and CI pipelines.
