"""Unified CLI: so-ops {init,triage,health,scan,status,config-check,test-notify}."""

from __future__ import annotations

import argparse
import sys


def cmd_init(args):
    from so_ops.init import run_init
    run_init()


def cmd_triage(args, cfg):
    from so_ops.tools.triage import run_triage
    run_triage(cfg, dry_run=args.dry_run)


def cmd_health(args, cfg):
    from so_ops.tools.health import run_health
    run_health(cfg)


def cmd_scan(args, cfg):
    from so_ops.tools.vulnscan import run_vulnscan
    run_vulnscan(cfg, scan_type=args.type)


def cmd_status(args, cfg):
    from so_ops.state import ToolState
    state_dir = cfg.paths.data_dir / "state"
    for tool in ("triage", "health", "vulnscan"):
        st = ToolState(tool, state_dir)
        print(f"{tool:10s}: {st.as_status_line()}")


def cmd_config_check(args, cfg):
    print("Config loaded successfully from:", args._config_path or "(auto-detected)")
    print(f"  ES host:      {cfg.elasticsearch.host}")
    print(f"  ES indices:   suricata={cfg.elasticsearch.indices.suricata}")
    print(f"                zeek={cfg.elasticsearch.indices.zeek}")
    print(f"                detections={cfg.elasticsearch.indices.detections}")
    print(f"  Ollama:       {cfg.ollama.url} / {cfg.ollama.model}")
    enabled = [n for n, c in cfg.notifications.items() if c.get("enabled")]
    print(f"  Notify:       {', '.join(enabled) if enabled else 'none enabled'}")
    print(f"  Data dir:     {cfg.paths.data_dir}")
    print(f"  Triage noise: {len(cfg.triage.auto_noise.signatures)} signatures")
    print(f"  Scan targets: {cfg.vulnscan.targets}")
    if cfg.network.zones:
        print(f"  Net zones:    {len(cfg.network.zones)} configured")
        for z in cfg.network.zones:
            print(f"                {z.cidr} = {z.name}")


def cmd_test_notify(args, cfg):
    from so_ops.clients.notify import notify_all
    print("Sending test notification to all enabled providers...")
    results = notify_all(
        cfg.notifications,
        "[so-ops] Test notification",
        "This is a test from so-ops test-notify.\n\nIf you see this, notifications are working.",
        short="so-ops test notification OK",
    )
    if not results:
        print("  No notification providers enabled in config.")
    for provider, ok in results.items():
        print(f"  {provider}: {'OK' if ok else 'FAILED'}")


def main():
    parser = argparse.ArgumentParser(prog="so-ops", description="Security Onion operations toolkit")
    parser.add_argument("--config", dest="config_path", default=None,
                        help="Path to config.toml (default: auto-detect)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Interactive setup wizard — create config.toml")

    p_triage = sub.add_parser("triage", help="Run alert triage")
    p_triage.add_argument("--dry-run", action="store_true", help="Skip LLM and notifications")

    sub.add_parser("health", help="Run daily health check")

    p_scan = sub.add_parser("scan", help="Run vulnerability scan")
    p_scan.add_argument("--type", choices=["nmap", "nuclei", "all"], default="all",
                        help="Scan type (default: all)")

    sub.add_parser("status", help="Show last run times/results")
    sub.add_parser("config-check", help="Validate config.toml")
    sub.add_parser("test-notify", help="Send test notification to all enabled providers")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # init runs before config load (config may not exist yet)
    if args.command == "init":
        cmd_init(args)
        return

    # Store config path on args for config-check display
    args._config_path = args.config_path

    # Load config
    from pathlib import Path
    from so_ops.config import load_config
    config_path = Path(args.config_path) if args.config_path else None
    cfg = load_config(config_path)

    dispatch = {
        "triage": cmd_triage,
        "health": cmd_health,
        "scan": cmd_scan,
        "status": cmd_status,
        "config-check": cmd_config_check,
        "test-notify": cmd_test_notify,
    }
    dispatch[args.command](args, cfg)
