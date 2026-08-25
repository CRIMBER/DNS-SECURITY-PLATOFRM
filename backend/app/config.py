"""Application settings and risk-policy configuration.

Two distinct kinds of configuration live here:

* ``Settings``   - deployment concerns (paths, host, port). Environment driven.
* ``RiskConfig`` - detection policy (weights, thresholds, rule points). File
  driven, from ``config/risk_config.json``, so the security policy can be
  tuned and re-tuned without touching a line of Python.

No weight or threshold is hardcoded anywhere else in the codebase.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# backend/app/config.py -> backend/app -> backend -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_DIR = Path(__file__).resolve().parent


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    """Deployment configuration, overridable by environment variable."""

    app_name: str = "AI-Powered Adaptive DNS Security & Threat Intelligence Platform"
    version: str = "0.1.0-prototype"
    host: str = "127.0.0.1"
    port: int = 8000
    database_path: Path = PROJECT_ROOT / "data" / "platform.db"
    risk_config_path: Path = PROJECT_ROOT / "config" / "risk_config.json"
    frontend_dir: Path = PROJECT_ROOT / "frontend"
    log_level: str = "info"

    # -- DNS gateway (phase 2) ---------------------------------------------
    # The gateway binds a non-privileged port by default so no administrator
    # rights are needed. The upstream resolver is referenced from here and
    # nowhere else, so no provider is hardcoded through the codebase.
    dns_enabled: bool = True
    dns_listen_host: str = "127.0.0.1"
    dns_listen_port: int = 5353
    upstream_dns_host: str = "1.1.1.1"
    upstream_dns_port: int = 53
    dns_upstream_timeout: float = 3.0
    dns_tcp_enabled: bool = True
    dns_block_mode: str = "NXDOMAIN"
    dns_cache_enabled: bool = True
    dns_cache_max_entries: int = 2000
    dns_cache_max_ttl: int = 300
    dns_log_client_ip: str = "loopback_only"
    """none | loopback_only | always.

    Defaults to recording the client address only when it is a loopback
    address, so a local prototype stays useful without storing the network
    addresses of real users.
    """

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            host=_env("DNSSEC_HOST", "127.0.0.1"),
            port=int(_env("DNSSEC_PORT", "8000")),
            database_path=Path(_env("DNSSEC_DB_PATH", str(PROJECT_ROOT / "data" / "platform.db"))),
            risk_config_path=Path(
                _env("DNSSEC_RISK_CONFIG", str(PROJECT_ROOT / "config" / "risk_config.json"))
            ),
            frontend_dir=Path(_env("DNSSEC_FRONTEND_DIR", str(PROJECT_ROOT / "frontend"))),
            log_level=_env("DNSSEC_LOG_LEVEL", "info"),
            dns_enabled=_flag("DNS_ENABLED", True),
            dns_listen_host=_env("DNS_LISTEN_HOST", "127.0.0.1"),
            dns_listen_port=int(_env("DNS_LISTEN_PORT", "5353")),
            upstream_dns_host=_env("UPSTREAM_DNS_HOST", "1.1.1.1"),
            upstream_dns_port=int(_env("UPSTREAM_DNS_PORT", "53")),
            dns_upstream_timeout=float(_env("DNS_UPSTREAM_TIMEOUT", "3.0")),
            dns_tcp_enabled=_flag("DNS_TCP_ENABLED", True),
            dns_block_mode=_env("DNS_BLOCK_MODE", "NXDOMAIN").upper(),
            dns_cache_enabled=_flag("DNS_CACHE_ENABLED", True),
            dns_cache_max_entries=int(_env("DNS_CACHE_MAX_ENTRIES", "2000")),
            dns_cache_max_ttl=int(_env("DNS_CACHE_MAX_TTL", "300")),
            dns_log_client_ip=_env("DNS_LOG_CLIENT_IP", "loopback_only").lower(),
        )

    @property
    def dns_listen_address(self) -> str:
        return "{}:{}".format(self.dns_listen_host, self.dns_listen_port)

    @property
    def upstream_address(self) -> str:
        return "{}:{}".format(self.upstream_dns_host, self.upstream_dns_port)


class RiskConfig:
    """Typed, read-only accessor over ``config/risk_config.json``.

    Access is by dotted path with a required default, so a malformed or
    partially edited config file degrades to sane behaviour instead of raising
    a ``KeyError`` in the middle of an analysis request.
    """

    def __init__(self, data: Dict[str, Any], source: Optional[Path] = None) -> None:
        self._data = data
        self.source = source

    @classmethod
    def load(cls, path: Path) -> "RiskConfig":
        with open(path, "r", encoding="utf-8") as handle:
            return cls(json.load(handle), source=path)

    def get(self, dotted_path: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted_path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    # -- convenience accessors used across the pipeline ---------------------

    @property
    def version(self) -> str:
        return self._data.get("version", "unknown")

    @property
    def weights(self) -> Dict[str, float]:
        raw = self.get("weights", {}) or {}
        return {k: float(v) for k, v in raw.items() if not k.startswith("_")}

    @property
    def bands(self) -> List[Dict[str, Any]]:
        return self.get("thresholds.bands", []) or []

    def rule(self, name: str) -> Dict[str, Any]:
        """Points/threshold parameters for one lexical rule."""
        return self.get("lexical.rules." + name, {}) or {}

    def override(self, name: str) -> Dict[str, Any]:
        return self.get("overrides." + name, {}) or {}

    def classify(self, score: float) -> Dict[str, str]:
        """Map a 0-100 score onto its configured classification and decision."""
        rounded = int(round(score))
        for band in self.bands:
            if int(band["min"]) <= rounded <= int(band["max"]):
                return {
                    "classification": band["classification"],
                    "decision": band["decision"],
                }
        # Defensive fallback: a score outside every configured band is treated
        # as suspicious rather than silently allowed.
        return {"classification": "SUSPICIOUS", "decision": "MONITOR"}

    def public_view(self) -> Dict[str, Any]:
        """The subset of policy safe to expose via ``GET /api/config``.

        Showing an analyst (or a judge) the exact policy that produced a
        verdict is a feature, not a leak - but internal comment keys are
        stripped.
        """
        return {
            "version": self.version,
            "weights": self.weights,
            "bands": [
                {k: v for k, v in band.items() if not k.startswith("_")}
                for band in self.bands
            ],
            "unknown_domain_policy": {
                "treat_unknown_as_safe": self.get(
                    "unknown_domain_policy.treat_unknown_as_safe", False
                ),
                "unknown_confidence": self.get(
                    "unknown_domain_policy.unknown_confidence", 0.0
                ),
            },
            "overrides": {
                name: {k: v for k, v in body.items() if not k.startswith("_")}
                for name, body in (self.get("overrides", {}) or {}).items()
                if not name.startswith("_") and isinstance(body, dict)
            },
        }


# -- data-file loading ------------------------------------------------------


def load_json_data(*relative_parts: str) -> Dict[str, Any]:
    """Load a JSON data file bundled inside ``backend/app``."""
    path = APP_DIR.joinpath(*relative_parts)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_wordlist(*relative_parts: str) -> frozenset:
    """Load a whitespace-separated wordlist, ignoring ``#`` comment lines."""
    path = APP_DIR.joinpath(*relative_parts)
    words = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.lstrip().startswith("#"):
                continue
            words.update(line.split())
    return frozenset(words)


# -- module-level singletons ------------------------------------------------

_settings: Optional[Settings] = None
_risk_config: Optional[RiskConfig] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


def get_risk_config() -> RiskConfig:
    global _risk_config
    if _risk_config is None:
        _risk_config = RiskConfig.load(get_settings().risk_config_path)
    return _risk_config


def reload_risk_config() -> RiskConfig:
    """Re-read the policy file. Used by tests and by future hot-reload."""
    global _risk_config
    _risk_config = RiskConfig.load(get_settings().risk_config_path)
    return _risk_config
