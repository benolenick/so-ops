# so-ops

LLM-powered alert triage, daily health reports, and vulnerability scanning for [Security Onion](https://securityonion.net/).

A free, open-source companion tool that fills gaps in the SO ecosystem: automated alert classification with local LLMs, morning briefing emails, and scheduled nmap/nuclei scanning — all without cloud dependencies.

## Features

### Alert Triage (`so-ops triage`)
Queries Suricata IDS alerts from Elasticsearch, groups them by signature, and uses a local LLM (via Ollama) to classify each group as NOISE / LOW / MEDIUM / HIGH. Known-benign signatures are auto-cleared. HIGH alerts trigger instant notifications.

```
## Verdict Breakdown
- **HIGH**: 2 (1.3%)
- **MEDIUM**: 8 (5.3%)
- **LOW**: 12 (8.0%)
- **NOISE**: 128 (85.3%)

## HIGH Priority - Investigate Immediately
- **ET EXPLOIT Possible CVE-2024-1234** | 203.0.113.50 -> 192.168.0.200:443
  - Reason: External IP targeting SO manager with known exploit signature
  - Action: Check SO manager logs, verify patch status
```

### Daily Health Report (`so-ops health`)
Collects 24h metrics from Suricata, Zeek, Sigma detections, and data stream health. Generates an AI morning briefing summarizing what matters.

### Vulnerability Scanning (`so-ops scan`)
Runs nmap + vulners and/or nuclei against your network. Produces a report with CVE findings and an AI executive summary.

## Requirements

- **Security Onion 2.4+** with Elasticsearch enabled
- **Python 3.11+** (ships with Security Onion 2.4)
- **pip** (Python package installer — see install steps below if missing)
- **Ollama** with a model pulled (e.g., `ollama pull qwen3:14b`)
- **nmap** (for vulnerability scanning)
- **Docker** (for nuclei scanning, optional)

so-ops has **zero third-party Python dependencies** — it only uses the Python standard library.

## Install

### Option A — pip install (recommended)

```bash
pip install git+https://github.com/benolenick/so-ops.git
```

If you get `-bash: pip: command not found`, install pip first:

```bash
# RHEL / Oracle Linux / Rocky (typical Security Onion base)
sudo dnf install python3-pip

# Debian / Ubuntu
sudo apt install python3-pip

# Or use the pip module directly (works without installing pip separately)
python3 -m pip install git+https://github.com/benolenick/so-ops.git
```

### Option B — clone and install

```bash
git clone https://github.com/benolenick/so-ops.git
cd so-ops
python3 -m pip install .
```

## Quick Start

```bash
# Interactive setup (creates config.toml, tests connections)
so-ops init

# Or manually: copy and edit the example config
cp config.example.toml config.toml
chmod 600 config.toml
# Edit config.toml with your values

# Verify
so-ops config-check
so-ops test-notify

# Run
so-ops triage --dry-run    # test without LLM
so-ops triage              # full triage
so-ops health              # daily health report
so-ops scan --type nmap    # vulnerability scan
```

## Configuration

`so-ops init` walks you through setup interactively. Configuration lives in `config.toml` (searched in CWD, then `~/.config/so-ops/`, or set `$SO_OPS_CONFIG`).

Key sections:

| Section | Purpose |
|---------|---------|
| `[elasticsearch]` | SO manager connection + index names |
| `[ollama]` | Local LLM endpoint + model |
| `[notifications.*]` | Email, Discord, Slack, ntfy, Gotify, SMS, webhook |
| `[network.zones]` | Your subnet layout (helps LLM classify alerts) |
| `[triage]` | Lookback window, auto-noise signatures, escalation rules |
| `[vulnscan]` | Scan targets, nmap/nuclei options |

See [config.example.toml](config.example.toml) for all options.

## Notifications

so-ops supports multiple notification providers simultaneously. Enable any combination in config:

- **Email** — SMTP SSL
- **Discord** — Webhook
- **Slack** — Webhook
- **ntfy** — Push notifications (self-hosted or ntfy.sh)
- **Gotify** — Self-hosted push
- **SMS** — Twilio
- **Webhook** — Generic HTTP POST

## Systemd Timers

`so-ops init` can generate systemd units for automated scheduling:

- **Triage**: every 15 minutes
- **Health**: daily at 7:10 AM
- **Vuln scan (nmap)**: Sunday 2 AM
- **Vuln scan (nuclei)**: Wednesday 2 AM

## How It Works

1. **Elasticsearch queries** use the standard Security Onion index patterns (`logs-suricata.alerts-so`, `logs-zeek-so`, etc.) which are consistent across all SO installs
2. **LLM classification** runs locally via Ollama — no data leaves your network
3. **Network zone context** from your config is injected into LLM prompts so it understands which IPs are internal vs. external
4. **State tracking** via JSON files prevents re-processing alerts and tracks run history

## License

MIT
