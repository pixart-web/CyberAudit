"""Validate production settings without starting a service or printing secrets."""

from __future__ import annotations

import json

from cyberaudit.config import Settings


def main() -> None:
    settings = Settings()
    if not settings.production_like:
        raise SystemExit("ENVIRONMENT must be staging, production, on_premises or ha")
    print(
        json.dumps(
            {
                "valid": True,
                "environment": settings.environment,
                "authentication_mode": settings.authentication_mode,
                "secret_provider": settings.secret_provider,
                "object_storage_provider": settings.object_storage_provider,
                "runner_type": settings.runner_type,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
