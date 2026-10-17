from __future__ import annotations

from typing import Optional, Sequence

from src.cli import main as cli_main


def main(argv: Optional[Sequence[str]] = None) -> int:
    return cli_main(list(argv) if argv is not None else None)


if __name__ == "__main__":
    raise SystemExit(main())
