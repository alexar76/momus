"""MOMUS entrypoint — the AIMarket v2 surface comes from oracle-core."""

from __future__ import annotations

import os

from momus.app import build_app

app = build_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        "momus.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("MOMUS_PORT", "9400")),
        reload=False,
    )


if __name__ == "__main__":
    main()
