"""``skyline-api``: serve the API with uvicorn."""

from __future__ import annotations

import uvicorn

from skyline_api.app import create_app
from skyline_api.settings import ApiSettings
from skyline_core.logging import configure_logging


def main() -> None:
    settings = ApiSettings()
    configure_logging(settings.log_level)
    uvicorn.run(
        create_app(settings),
        # Inside the container; only the web service is published to the host (Compose).
        host="0.0.0.0",  # noqa: S104
        port=settings.port,
        proxy_headers=False,  # client IPs come from trusted_proxy_hops, not uvicorn
        server_header=False,
        date_header=False,
        limit_concurrency=settings.max_concurrency,
        access_log=False,  # our access log strips query strings
        log_config=None,
    )


if __name__ == "__main__":
    main()
