# HREA

HREA is a lightweight reverse-engineering and conversion CLI for identifying binary characteristics, analyzing file intent, and generating scaffolded conversion output for a selected target language.

## Installation

Install the wheel from the built artifact:

```bash
pip install hrea-1.0.1-py3-none-any.whl
```

Then run:

```bash
hrea --help
hrea --version
```

## Features

- Detect file type, architecture, packer markers, and purpose heuristically
- Analyze an input binary with optional GGUF model loading
- Use local config defaults for model path and output directory
- Generate placeholder conversion scaffolding for a target language
- Check installed tooling and runtime environment with `hrea doctor`
- Output machine-readable JSON for scripting and CI use

## CLI overview

```bash
hrea analyze <path> [--model PATH] [--json] [--no-ai]
hrea detect <path> [--json]
hrea convert <path> -t python -o ./out [--model PATH] [--json]
hrea list-tools [--json]
hrea doctor [--json]
hrea config set default_model /path/to/model.gguf
hrea config get default_model
hrea config list
hrea version
```

## Model loading

The `analyze` and `convert` flows accept a GGUF model path through the `--model` flag. If the package is installed with `llama-cpp-python`, the CLI will attempt to load the model when AI mode is enabled.

Example:

```bash
hrea analyze ./my_app.exe --model ./codellama.gguf --json
```

If a model is not provided, the CLI will still analyze the file with heuristics unless `--no-ai` is supplied. The JSON response includes fields such as:

```json
{
  "ai_mode": "ai-enabled",
  "model_loaded": true,
  "model_status": "model_loaded"
}
```

You can also set a default model once in config:

```bash
hrea config set default_model /path/to/model.gguf
```

## Configuration

The config file is stored under the user config directory and supports defaults for the model path and output folder.

```bash
hrea config set default_target js
hrea config get default_target
hrea config list
```

## Examples

```bash
hrea analyze ./example.exe --json
hrea detect ./example.exe
hrea convert ./example.exe -t python -o ./out --json
hrea doctor
```

## Notes

- The project is intentionally dependency-light and stdout-friendly for shell scripts and CI.
- JSON mode prints exactly one JSON object to stdout and suppresses other output.
- The CLI is designed to be used as a standard installed command: `hrea ...`.
