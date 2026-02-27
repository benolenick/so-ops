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

## Where to Install

so-ops does **not** need to run on your Security Onion box. It connects to SO's Elasticsearch over HTTPS, so it can run from any machine on your network that can reach the SO manager on port 9200.

**Recommended: install on a separate machine**, not on the SO sensor itself.

- **Don't pollute the sensor** — SO is a tuned appliance; adding packages and workloads can cause issues
- **Ollama needs resources** — a 14B-parameter LLM wants RAM/GPU that shouldn't compete with Elasticsearch and Zeek
- **SO's firewall is restrictive** — installing packages directly on SO can be difficult (pip/git may be blocked or missing)
- **Vuln scans from outside SO** give you the external attacker's perspective

A small Linux VM, a spare workstation, or even a Raspberry Pi 5 will work — the only network requirement is HTTPS access to your SO manager's Elasticsearch port (default 9200).

## Requirements

| Requirement | Purpose | Notes |
|-------------|---------|-------|
| **Security Onion 2.4+** | Data source | Elasticsearch must be enabled |
| **Python 3.11+** | Runtime | Ships with most modern distros |
| **Ollama** | Local LLM | Install from [ollama.com](https://ollama.com), then `ollama pull qwen3:14b` |
| **nmap** | Vulnerability scanning | Optional — only for `so-ops scan` |
| **Docker** | Nuclei scanning | Optional — only for `so-ops scan --type nuclei` |

so-ops has **zero third-party Python dependencies** — it only uses the Python standard library.

## Install

### Option A — pip install (recommended)

```bash
pip install git+https://github.com/benolenick/so-ops.git
```

If you get `-bash: pip: command not found`, install pip first:

```bash
# RHEL / Oracle Linux / Rocky
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

## Setup

### What you need before running `so-ops init`

The only **essential** credential is your Security Onion Elasticsearch password. Everything else is either auto-detected or optional.

| What | Where to find it | Required? |
|------|-----------------|-----------|
| **SO manager IP/hostname** | Your Security Onion manager's address (e.g. `https://10.0.0.50:9200`) | Yes |
| **Elasticsearch password** | On the SO manager, run: `sudo so-user show` to list users, or check SOC web UI under Administration. The default user is `so_elastic`. | Yes |
| **Ollama URL** | Defaults to `http://localhost:11434` if Ollama is on the same box as so-ops. If Ollama runs elsewhere, use that machine's IP. | Yes |
| **Notification credentials** | Discord/Slack webhook URL, email SMTP credentials, ntfy topic, etc. | No — but recommended |
| **Network subnets** | Your monitored CIDRs (e.g. `192.168.1.0/24`). Helps the LLM understand which IPs are internal. | No — but improves triage accuracy |

### Getting the Elasticsearch password

On your **Security Onion manager**, run:

```bash
# Show the elastic user password
sudo so-elastic-auth

# Or if that's not available on your SO version, check:
sudo so-user show
```

The default username is `so_elastic`. This is the same account used by SOC and Kibana to query Elasticsearch.

### Running the setup wizard

```bash
so-ops init
```

The wizard will:
1. Ask for your SO manager URL and ES credentials, then **test the connection**
2. Auto-discover your SO data stream indices
3. Ask for your Ollama URL, then **test the connection** and list available models
4. Walk through notification providers (all optional)
5. Ask for your network zones and scan targets
6. Write `config.toml` (permissions set to 600)
7. Optionally generate systemd timer units for automated scheduling

### Manual setup (alternative)

```bash
cp config.example.toml config.toml
chmod 600 config.toml
# Edit config.toml — at minimum fill in:
#   [elasticsearch] host, user, password
#   [ollama] url, model
```

### Verify and run

```bash
so-ops config-check        # validate config
so-ops test-notify         # test notification providers
so-ops triage --dry-run    # test triage without LLM calls
so-ops triage              # full triage run
so-ops health              # daily health report
so-ops scan --type nmap    # vulnerability scan
```

## Configuration Reference

Configuration lives in `config.toml` (searched in CWD, then `~/.config/so-ops/`, or set `$SO_OPS_CONFIG`).

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
