# Changelog

## 1.0.1 - 2026-10-25

### Why this version exists

This patch release improves confidence in the existing implementation. The
source was tested against a Functional Requirements Specification using the
offline `niwoec` verifier, and the test suite was expanded to cover every
requirement mapped to the `src/` package.

### Changes

- Added focused behavioral tests for all 24 `src/` requirements.
- Verified model-loading, file detection, configuration, conversion, tool
  diagnostics, parser behavior, CLI commands, and error exit codes.
- Added `src_requirements.frs` as the source-level requirements contract.
- Added niwoec verification to the release validation process.
- Updated documentation and package version metadata.

### Verification

- Pytest: 32 tests passed.
- niwoec: 24 requirements mapped, tested, and satisfied.
- niwoec findings: 0.

## 1.0.0 - Initial release

### Why this version exists

This was the first packaged HREA release after replacing the original curses
demo with the documented argparse CLI and splitting the implementation into
the `src/` package.

### Changes

- Added the `analyze`, `convert`, `detect`, `list-tools`, `doctor`, `config`,
  and `version` commands.
- Added JSON output and documented CLI flags.
- Added heuristic file analysis and conversion scaffolding.
- Added GGUF model loading through `llama-cpp-python`.
- Added setuptools packaging and the `hrea` console entry point.
- Added the initial pytest regression suite and README documentation.