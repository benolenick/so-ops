"""TOML config loader with typed dataclasses."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ESIndicesConfig:
    suricata: str = "logs-suricata.alerts-so"
    zeek: str = "logs-zeek-so"
    detections: str = "logs-detections.alerts-so"
    syslog: str = "logs-syslog-so"
    data_streams: str = "*so*"


@dataclass
class ESConfig:
    host: str
    user: str
    password: str
    verify_ssl: bool = False
    indices: ESIndicesConfig = field(default_factory=ESIndicesConfig)


@dataclass
class OllamaConfig:
    url: str
    model: str


@dataclass
class PathsConfig:
    data_dir: Path

    def __post_init__(self):
        self.data_dir = Path(os.path.expanduser(str(self.data_dir)))


@dataclass
class TriageEscalation:
    minimum_medium: list[str] = field(default_factory=list)
    minimum_high: list[str] = field(default_factory=list)


@dataclass
class TriageAutoNoise:
    signatures: list[str] = field(default_factory=list)


@dataclass
class TriageConfig:
    lookback_hours: int = 24
    max_alerts_per_run: int = 500
    max_alerts_per_query: int = 2000
    max_batch_size: int = 50
    llm_temperature: float = 0.1
    auto_noise: TriageAutoNoise = field(default_factory=TriageAutoNoise)
    escalation: TriageEscalation = field(default_factory=TriageEscalation)


@dataclass
class HealthConfig:
    llm_temperature: float = 0.3


@dataclass
class VulnscanConfig:
    targets: list[str] = field(default_factory=lambda: ["192.168.0.0/24"])
    nmap_bin: str = "/usr/bin/nmap"
    nmap_args: str = "-sV --script=vulners -T4 --open"
    nuclei_docker: str = "projectdiscovery/nuclei:latest"
    nuclei_severity: str = "medium,high,critical"


@dataclass
class NetworkZone:
    cidr: str
    name: str
    description: str


@dataclass
class NetworkConfig:
    internal_prefixes: list[str] = field(default_factory=lambda: ["192.168.", "10.", "172.16."])
    zones: list[NetworkZone] = field(default_factory=list)


@dataclass
class Config:
    elasticsearch: ESConfig
    ollama: OllamaConfig
    paths: PathsConfig
    notifications: dict[str, dict]
    triage: TriageConfig
    health: HealthConfig
    vulnscan: VulnscanConfig
    network: NetworkConfig


def _find_config_file() -> Path:
    """Search for config.toml in standard locations."""
    env = os.environ.get("SO_OPS_CONFIG")
    if env:
        p = Path(env)
        if p.is_file():
            return p
        print(f"so-ops: $SO_OPS_CONFIG points to {p} which does not exist", file=sys.stderr)
        sys.exit(1)

    candidates = [
        Path.cwd() / "config.toml",
        Path.home() / ".config" / "so-ops" / "config.toml",
    ]
    for c in candidates:
        if c.is_file():
            return c

    print(
        "so-ops: config.toml not found. Searched:\n"
        "  $SO_OPS_CONFIG\n"
        f"  {candidates[0]}\n"
        f"  {candidates[1]}\n"
        "Run 'so-ops init' to create one, or copy config.example.toml.",
        file=sys.stderr,
    )
    sys.exit(1)


def load_config(path: Path | None = None) -> Config:
    """Load and validate config from TOML file."""
    if path is None:
        path = _find_config_file()

    with open(path, "rb") as f:
        raw = tomllib.load(f)

    try:
        es_raw = dict(raw["elasticsearch"])
        indices_raw = es_raw.pop("indices", {})
        es = ESConfig(**es_raw, indices=ESIndicesConfig(**indices_raw))

        ollama = OllamaConfig(**raw["ollama"])
        paths = PathsConfig(**raw.get("paths", {"data_dir": "~/so-ops-data"}))

        # Notifications: collect all [notifications.*] sections
        notifications: dict[str, dict] = {}
        notif_raw = raw.get("notifications", {})
        for provider_name, provider_cfg in notif_raw.items():
            if isinstance(provider_cfg, dict):
                notifications[provider_name] = dict(provider_cfg)

        # Backwards compat: old [email] and [sms] top-level sections
        if "email" in raw and "email" not in notifications:
            email_raw = dict(raw["email"])
            email_raw.setdefault("enabled", True)
            notifications["email"] = email_raw
        if "sms" in raw and "sms" not in notifications:
            sms_raw = dict(raw["sms"])
            notifications["sms"] = sms_raw

        triage_raw = dict(raw.get("triage", {}))
        auto_noise_raw = triage_raw.pop("auto_noise", {})
        escalation_raw = triage_raw.pop("escalation", {})
        triage = TriageConfig(
            **triage_raw,
            auto_noise=TriageAutoNoise(**auto_noise_raw),
            escalation=TriageEscalation(**escalation_raw),
        )

        health = HealthConfig(**raw.get("health", {}))
        vulnscan = VulnscanConfig(**raw.get("vulnscan", {}))

        # Network config with zones
        net_raw = dict(raw.get("network", {}))
        zones_raw = net_raw.pop("zones", [])
        zones = [NetworkZone(**z) for z in zones_raw]
        network = NetworkConfig(**net_raw, zones=zones)

    except (KeyError, TypeError) as exc:
        print(f"so-ops: config error in {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    return Config(
        elasticsearch=es,
        ollama=ollama,
        paths=paths,
        notifications=notifications,
        triage=triage,
        health=health,
        vulnscan=vulnscan,
        network=network,
    )
