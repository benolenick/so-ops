"""Tests for config loading."""

from so_ops.config import load_config, Config


def test_load_example_config(example_config_path):
    """config.example.toml must parse into a valid Config."""
    cfg = load_config(example_config_path)
    assert isinstance(cfg, Config)
    assert "9200" in cfg.elasticsearch.host
    assert cfg.elasticsearch.user == "so_elastic"
    assert cfg.elasticsearch.indices.suricata == "logs-suricata.alerts-so"
    assert cfg.elasticsearch.indices.zeek == "logs-zeek-so"
    assert cfg.ollama.model == "qwen3:14b"
    assert "email" in cfg.notifications
    assert cfg.notifications["email"]["enabled"] is False
    assert len(cfg.triage.auto_noise.signatures) == 4
    assert "ET TROJAN" in cfg.triage.escalation.minimum_high
    assert cfg.vulnscan.targets == ["192.168.0.0/24"]
    assert "192.168." in cfg.network.internal_prefixes
    assert len(cfg.network.zones) == 2
    assert cfg.network.zones[0].cidr == "192.168.0.0/24"


def test_config_paths_expands_tilde(example_config_path):
    """data_dir should expand ~ to a real path."""
    cfg = load_config(example_config_path)
    assert "~" not in str(cfg.paths.data_dir)
