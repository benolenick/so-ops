"""Tests for triage classification logic (no network required)."""

from so_ops.tools.triage import (
    _classify_auto_noise,
    _group_alerts,
    _enforce_minimum_severity,
)


def _make_alert(rule_name="ET INFO test", source_ip="192.168.2.10", dest_ip="8.8.8.8"):
    return {
        "id": "abc123",
        "timestamp": "2026-02-24T12:00:00Z",
        "rule_name": rule_name,
        "rule_severity": "3",
        "sig_severity": "Informational",
        "category": "Misc",
        "source_ip": source_ip,
        "source_port": "12345",
        "dest_ip": dest_ip,
        "dest_port": "443",
        "community_id": "",
        "ruleset": "et/open",
        "action": "allowed",
    }


NOISE_SIGS = {
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
    "ET INFO Microsoft Connection Test",
}


def test_auto_noise_classification():
    alerts = [
        _make_alert("ET INFO Session Traversal Utilities for NAT (STUN Binding Request)"),
        _make_alert("ET SCAN Potential SSH Scan"),
        _make_alert("ET INFO Microsoft Connection Test"),
    ]
    noise, review = _classify_auto_noise(alerts, NOISE_SIGS)
    assert len(noise) == 2
    assert len(review) == 1
    assert review[0]["rule_name"] == "ET SCAN Potential SSH Scan"
    assert noise[0]["triage_verdict"] == "NOISE"


def test_group_alerts():
    alerts = [
        _make_alert("RuleA", "10.0.0.1"),
        _make_alert("RuleA", "10.0.0.1"),
        _make_alert("RuleA", "10.0.0.2"),
        _make_alert("RuleB", "10.0.0.1"),
    ]
    groups = _group_alerts(alerts)
    assert len(groups) == 3
    assert len(groups["RuleA|10.0.0.1"]) == 2


def test_enforce_minimum_severity():
    min_med = ["ET SCAN", "ET EXPLOIT"]
    min_high = ["ET TROJAN", "ET MALWARE"]

    # NOISE -> MEDIUM for scan
    assert _enforce_minimum_severity("ET SCAN SSH brute", "NOISE", min_med, min_high) == "MEDIUM"
    # LOW -> HIGH for trojan
    assert _enforce_minimum_severity("ET TROJAN Generic", "LOW", min_med, min_high) == "HIGH"
    # HIGH stays HIGH for trojan
    assert _enforce_minimum_severity("ET TROJAN Generic", "HIGH", min_med, min_high) == "HIGH"
    # Non-matching stays as-is
    assert _enforce_minimum_severity("ET INFO something", "LOW", min_med, min_high) == "LOW"
