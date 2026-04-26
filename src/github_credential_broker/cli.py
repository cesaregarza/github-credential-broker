from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from github_credential_broker.errors import ConfigurationError
from github_credential_broker.policy import load_policy


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the GitHub credential broker.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    uvicorn.run(
        "github_credential_broker.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def validate_policy_main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Validate a GitHub credential broker policy file.")
    parser.add_argument("policy_path", type=Path)
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy_path)
    except ConfigurationError as exc:
        parser.exit(1, f"policy invalid: {exc}\n")

    print(
        f"policy valid: {args.policy_path} "
        f"({len(policy.capabilities)} capabilities, {len(policy.grants)} grants)"
    )


if __name__ == "__main__":
    main()
