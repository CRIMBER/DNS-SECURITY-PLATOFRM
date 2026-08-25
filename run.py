"""Development entry point.

    python run.py            # http://127.0.0.1:8000
    python run.py --reload   # auto-restart on code change

Environment overrides: DNSSEC_HOST, DNSSEC_PORT, DNSSEC_DB_PATH,
DNSSEC_RISK_CONFIG, DNSSEC_LOG_LEVEL.
"""

import sys
from pathlib import Path

# Make `backend` importable without requiring an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn

from backend.app.config import get_settings


def main() -> None:
    settings = get_settings()
    reload_enabled = "--reload" in sys.argv

    print("=" * 74)
    print(" {}".format(settings.app_name))
    print(" Prototype {}   |   risk policy: {}".format(
        settings.version, settings.risk_config_path.name))
    print("-" * 74)
    print("  Dashboard : http://{}:{}/".format(settings.host, settings.port))
    print("  API docs  : http://{}:{}/api/docs".format(settings.host, settings.port))
    print("  Health    : http://{}:{}/api/health".format(settings.host, settings.port))
    print("=" * 74)

    uvicorn.run(
        "backend.app.main:app",
        host=settings.host,
        port=settings.port,
        reload=reload_enabled,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()
