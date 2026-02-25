"""Alert triage: query Suricata alerts, classify with LLM, notify on HIGH."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from so_ops.config import Config
from so_ops.clients.elasticsearch import SOElasticClient
from so_ops.clients.ollama import OllamaClient
from so_ops.clients.notify import notify_all
from so_ops.log import setup_logging
from so_ops.state import ToolState


def _extract_alert_summary(hit: dict) -> dict:
    """Extract key fields from an ES alert hit into a concise dict."""
    src = hit["_source"]
    rule = src.get("rule", {})
    source = src.get("source", {})
    dest = src.get("destination", {})

    alert_info = {}
    try:
        msg = json.loads(src.get("message", "{}"))
        alert_info = msg.get("alert", {})
    except (json.JSONDecodeError, TypeError):
        pass

    sig_sev = rule.get("metadata", {}).get("signature_severity", "Unknown")
    if isinstance(sig_sev, list):
        sig_sev = sig_sev[0] if sig_sev else "Unknown"

    return {
        "id": hit["_id"],
        "timestamp": src.get("@timestamp", ""),
        "rule_name": rule.get("name", alert_info.get("signature", "Unknown")),
        "rule_severity": rule.get("severity", "?"),
        "sig_severity": sig_sev,
        "category": alert_info.get("category", rule.get("category", "Unknown")),
        "source_ip": source.get("ip", "?"),
        "source_port": source.get("port", "?"),
        "dest_ip": dest.get("ip", "?"),
        "dest_port": dest.get("port", "?"),
        "community_id": src.get("network", {}).get("community_id", ""),
        "ruleset": rule.get("ruleset", ""),
        "action": rule.get("action", alert_info.get("action", "")),
    }


def _classify_auto_noise(alerts: list, noise_sigs: set) -> tuple[list, list]:
    """Separate known-noise alerts from those needing LLM review."""
    noise, needs_review = [], []
    for alert in alerts:
        if alert["rule_name"] in noise_sigs:
            alert["triage_verdict"] = "NOISE"
            alert["triage_reason"] = "Auto-classified: known benign signature"
            alert["triage_method"] = "auto"
            noise.append(alert)
        else:
            needs_review.append(alert)
    return noise, needs_review


def _group_alerts(alerts: list) -> dict[str, list]:
    """Group alerts by signature + source_ip."""
    groups: dict[str, list] = defaultdict(list)
    for alert in alerts:
        key = f"{alert['rule_name']}|{alert['source_ip']}"
        groups[key].append(alert)
    return dict(groups)


def _build_zone_context(zones) -> str:
    """Build network context string from configured zones."""
    if not zones:
        return (
            "- No specific network zones configured\n"
            "- Treat RFC1918 addresses as internal, everything else as external"
        )
    lines = []
    for z in zones:
        lines.append(f"- {z.cidr} = {z.name} ({z.description})")
    return "\n".join(lines)


def _build_triage_prompt(alerts: list, max_batch: int, zones) -> str:
    """Build an LLM prompt for triaging a group of similar alerts."""
    rule_name = alerts[0]["rule_name"]
    source_ip = alerts[0]["source_ip"]

    dests = set()
    for a in alerts[:max_batch]:
        dests.add(f"{a['dest_ip']}:{a['dest_port']}")

    times = [a["timestamp"] for a in alerts]
    time_range = f"{min(times)} to {max(times)}" if len(times) > 1 else times[0]
    sample = alerts[0]

    zone_context = _build_zone_context(zones)

    return f"""You are a Security Operations Center analyst triaging IDS alerts from a home/small business network.

Network context:
{zone_context}
- External IPs = internet traffic
- This is a home lab / small business, not an enterprise

Alert group to triage:
- Rule: {rule_name}
- Ruleset: {sample['ruleset']}
- Signature severity: {sample['sig_severity']}
- Rule severity: {sample['rule_severity']}
- Category: {sample['category']}
- Source IP: {source_ip}
- Destinations: {', '.join(list(dests)[:10])}
- Alert count: {len(alerts)}
- Time range: {time_range}
- Action: {sample['action']}

Classify this alert group into ONE of these categories:
- NOISE: Expected/benign traffic for this network type. No action needed.
- LOW: Minor finding, FYI only. Log and move on.
- MEDIUM: Worth investigating when convenient. Not urgent but notable.
- HIGH: Investigate immediately. Possible security incident.

Important classification guidelines:
- Any scanning activity (SSH, port scans) from EXTERNAL IPs = at least MEDIUM
- Any CVE-related signature = at least MEDIUM
- NTLM authentication on internal network in a small environment = LOW (expected)
- SNMP with default community strings = MEDIUM (misconfiguration risk)
- Be conservative: when in doubt, classify higher rather than lower

Respond in this exact JSON format (no other text):
{{"verdict": "NOISE|LOW|MEDIUM|HIGH", "reason": "Brief explanation (1-2 sentences)", "recommendation": "What to do about it (1 sentence)"}}
"""


def _enforce_minimum_severity(rule_name: str, verdict: str,
                              min_medium: list[str], min_high: list[str]) -> str:
    """Enforce minimum severity based on rule name patterns."""
    severity_order = {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    current = severity_order.get(verdict, 1)

    for pattern in min_high:
        if pattern in rule_name:
            return "HIGH" if current < 3 else verdict

    for pattern in min_medium:
        if rule_name.startswith(pattern) or pattern in rule_name:
            return "MEDIUM" if current < 2 else verdict

    return verdict


def _triage_with_llm(alerts: list, llm: OllamaClient, cfg_triage,
                     zones, log) -> dict:
    """Send alert group to LLM for triage classification."""
    prompt = _build_triage_prompt(alerts, cfg_triage.max_batch_size, zones)
    try:
        response = llm.generate(prompt, temperature=cfg_triage.llm_temperature)
        start = response.find("{")
        end = response.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(response[start:end])
            verdict = result.get("verdict", "LOW").upper()
            if verdict not in ("NOISE", "LOW", "MEDIUM", "HIGH"):
                verdict = "LOW"

            rule_name = alerts[0]["rule_name"]
            original_verdict = verdict
            verdict = _enforce_minimum_severity(
                rule_name, verdict,
                cfg_triage.escalation.minimum_medium,
                cfg_triage.escalation.minimum_high,
            )
            reason = result.get("reason", "")
            if verdict != original_verdict:
                reason += f" [Escalated from {original_verdict} due to rule pattern]"

            return {
                "verdict": verdict,
                "reason": reason,
                "recommendation": result.get("recommendation", ""),
            }
    except Exception as exc:
        log.warning("LLM triage failed for %s: %s", alerts[0]["rule_name"], exc)

    return {
        "verdict": "LOW",
        "reason": "LLM classification failed, defaulting to LOW",
        "recommendation": "Manual review recommended",
    }


def _log_triage_result(alert: dict, verdict_info: dict, jsonl_path: Path) -> dict:
    """Append a triage result to the JSONL log. Returns the entry."""
    entry = {
        "triaged_at": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert["id"],
        "alert_timestamp": alert["timestamp"],
        "rule_name": alert["rule_name"],
        "source_ip": alert["source_ip"],
        "dest_ip": alert["dest_ip"],
        "dest_port": alert["dest_port"],
        "rule_severity": alert["rule_severity"],
        "sig_severity": alert["sig_severity"],
        "verdict": verdict_info.get("verdict", alert.get("triage_verdict", "?")),
        "reason": verdict_info.get("reason", alert.get("triage_reason", "")),
        "recommendation": verdict_info.get("recommendation", ""),
        "method": verdict_info.get("method", alert.get("triage_method", "llm")),
    }
    with open(jsonl_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _generate_summary(results: list, detection_alerts: list,
                      run_time: float, summary_dir: Path) -> tuple[Path, str]:
    """Generate a human-readable triage summary markdown."""
    now = datetime.now(timezone.utc)
    summary_file = summary_dir / f"triage_{now.strftime('%Y%m%d_%H%M%S')}.md"

    verdict_counts: dict[str, int] = defaultdict(int)
    verdict_groups: dict[str, list] = defaultdict(list)
    for r in results:
        v = r["verdict"]
        verdict_counts[v] += 1
        verdict_groups[v].append(r)

    lines = [
        "# SO Alert Triage Summary",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Processing time:** {run_time:.1f}s",
        f"**Alerts processed:** {len(results)}",
        "",
        "## Verdict Breakdown",
    ]
    for v in ("HIGH", "MEDIUM", "LOW", "NOISE"):
        count = verdict_counts.get(v, 0)
        pct = (count / len(results) * 100) if results else 0
        bar = "#" * int(pct / 2)
        lines.append(f"- **{v}**: {count} ({pct:.1f}%) {bar}")
    lines.append("")

    if verdict_groups.get("HIGH"):
        lines.append("## HIGH Priority - Investigate Immediately")
        for r in verdict_groups["HIGH"]:
            lines.append(f"- **{r['rule_name']}** | {r['source_ip']} -> {r['dest_ip']}:{r['dest_port']}")
            lines.append(f"  - Reason: {r['reason']}")
            lines.append(f"  - Action: {r['recommendation']}")
        lines.append("")

    if verdict_groups.get("MEDIUM"):
        lines.append("## MEDIUM Priority - Investigate When Convenient")
        for r in verdict_groups["MEDIUM"]:
            lines.append(f"- **{r['rule_name']}** | {r['source_ip']} -> {r['dest_ip']}:{r['dest_port']}")
            lines.append(f"  - Reason: {r['reason']}")
            lines.append(f"  - Action: {r['recommendation']}")
        lines.append("")

    if verdict_groups.get("LOW"):
        lines.append("## LOW Priority - FYI")
        low_by_rule: dict[str, list] = defaultdict(list)
        for r in verdict_groups["LOW"]:
            low_by_rule[r["rule_name"]].append(r)
        for rule, items in low_by_rule.items():
            lines.append(f"- **{rule}**: {len(items)} alerts")
            if items[0]["reason"]:
                lines.append(f"  - {items[0]['reason']}")
        lines.append("")

    if verdict_groups.get("NOISE"):
        lines.append("## NOISE - Auto-Cleared")
        noise_by_rule: dict[str, int] = defaultdict(int)
        for r in verdict_groups["NOISE"]:
            noise_by_rule[r["rule_name"]] += 1
        for rule, count in sorted(noise_by_rule.items(), key=lambda x: -x[1]):
            lines.append(f"- {rule}: {count} alerts")
        lines.append("")

    if detection_alerts:
        lines.append("## Sigma Detection Alerts")
        for da in detection_alerts:
            src = da["_source"]
            rule = src.get("rule", {})
            lines.append(f"- **{rule.get('name', 'Unknown')}** (severity: {src.get('sigma_level', '?')})")
            lines.append(f"  - Time: {src.get('@timestamp', '?')}")
        lines.append("")

    summary_text = "\n".join(lines)
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_file.write_text(summary_text)
    return summary_file, summary_text


def run_triage(cfg: Config, dry_run: bool = False):
    """Main triage entry point."""
    data_dir = cfg.paths.data_dir
    log_dir = data_dir / "logs"
    state_dir = data_dir / "state"
    summary_dir = data_dir / "output" / "triage" / "summaries"
    jsonl_path = log_dir / "triage.jsonl"

    log = setup_logging("triage", log_dir)
    state = ToolState("triage", state_dir)
    state.start_run()

    es = SOElasticClient(cfg.elasticsearch)
    llm = OllamaClient(cfg.ollama)
    indices = cfg.elasticsearch.indices
    zones = cfg.network.zones

    noise_sigs = set(cfg.triage.auto_noise.signatures)
    start_time = time.time()

    # Determine starting point
    default_since = (datetime.now(timezone.utc) - timedelta(hours=cfg.triage.lookback_hours)).isoformat()
    since = state.get_cursor("last_timestamp", default_since)
    log.info("=" * 60)
    log.info("SO Alert Triage starting (dry_run=%s)", dry_run)
    log.info("Processing alerts since: %s", since)

    all_results = []
    all_detection_alerts = []

    while True:
        log.info("Fetching Suricata alerts (since %s)...", since)
        hits, total_available = es.fetch_suricata_alerts(
            since, cfg.triage.max_alerts_per_query, index=indices.suricata
        )
        log.info("Fetched %d alerts (total available: %d)", len(hits), total_available)

        if not hits:
            break

        # Fetch detection alerts only on first iteration
        if not all_detection_alerts:
            all_detection_alerts = es.fetch_detection_alerts(
                state.get_cursor("last_timestamp", default_since),
                index=indices.detections,
            )
            if all_detection_alerts:
                log.info("Also found %d Sigma detection alerts", len(all_detection_alerts))

        alerts = [_extract_alert_summary(hit) for hit in hits]
        auto_noise, needs_review = _classify_auto_noise(alerts, noise_sigs)
        log.info("Auto-classified %d as NOISE, %d need LLM review", len(auto_noise), len(needs_review))

        # Log auto-noise results
        for alert in auto_noise:
            entry = _log_triage_result(alert, {
                "verdict": "NOISE",
                "reason": alert["triage_reason"],
                "recommendation": "No action needed",
                "method": "auto",
            }, jsonl_path)
            all_results.append(entry)

        # Group remaining alerts for LLM triage
        if needs_review and not dry_run:
            groups = _group_alerts(needs_review)
            log.info("Grouped into %d unique signature+source combinations", len(groups))

            for i, (group_key, group_alerts_list) in enumerate(groups.items()):
                rule_name = group_alerts_list[0]["rule_name"]
                log.info("  [%d/%d] Triaging: %s (%d alerts)",
                         i + 1, len(groups), rule_name, len(group_alerts_list))

                verdict_info = _triage_with_llm(group_alerts_list, llm, cfg.triage, zones, log)
                verdict_info["method"] = "llm"
                log.info("    -> %s: %s", verdict_info["verdict"], verdict_info["reason"][:80])

                for alert in group_alerts_list:
                    entry = _log_triage_result(alert, verdict_info, jsonl_path)
                    all_results.append(entry)
        elif needs_review and dry_run:
            log.info("DRY RUN: skipping LLM triage for %d alerts", len(needs_review))

        # Update cursor
        since = hits[-1]["_source"]["@timestamp"]
        state.set_cursor("last_timestamp", since)

        if len(hits) < cfg.triage.max_alerts_per_query:
            break

    if not all_results:
        log.info("No new alerts to process.")
        run_time = time.time() - start_time
        state.finish_run(alerts=0)
        return

    run_time = time.time() - start_time
    summary_file, summary_text = _generate_summary(
        all_results, all_detection_alerts, run_time, summary_dir
    )
    log.info("Processed %d alerts in %.1fs", len(all_results), run_time)
    log.info("Summary: %s", summary_file)

    high_count = sum(1 for r in all_results if r["verdict"] == "HIGH")

    # Send notifications for HIGH severity alerts
    if not dry_run:
        high_alerts = [r for r in all_results if r["verdict"] == "HIGH"]
        if high_alerts:
            log.info("HIGH alerts detected (%d) — sending notifications...", len(high_alerts))
            alert_lines = [f"HIGH SEVERITY ALERT - {len(high_alerts)} alert(s) detected\n"]
            for a in high_alerts:
                alert_lines.append(f"  Rule: {a['rule_name']}")
                alert_lines.append(f"  Source: {a['source_ip']} -> {a['dest_ip']}:{a['dest_port']}")
                alert_lines.append(f"  Reason: {a['reason']}")
                alert_lines.append(f"  Recommendation: {a['recommendation']}")
                alert_lines.append("")
            alert_lines.append(f"Full summary:\n{summary_text}")

            sms_lines = [f"SO ALERT: {len(high_alerts)} HIGH severity"]
            seen_rules: set[str] = set()
            for a in high_alerts:
                if a["rule_name"] not in seen_rules:
                    sms_lines.append(f"- {a['rule_name']}")
                    sms_lines.append(f"  {a['source_ip']} -> {a['dest_ip']}")
                    seen_rules.add(a["rule_name"])

            notify_all(
                cfg.notifications,
                f"[SO ALERT] HIGH severity - {high_alerts[0]['rule_name']}",
                "\n".join(alert_lines),
                short="\n".join(sms_lines),
            )

        # Notify for high-severity Sigma detections
        if all_detection_alerts:
            high_sigma = [d for d in all_detection_alerts
                          if d["_source"].get("sigma_level") in ("high", "critical")]
            if high_sigma:
                log.info("Sigma detections (%d) — sending notifications...", len(high_sigma))
                det_rules: dict[str, int] = defaultdict(int)
                for d in high_sigma:
                    name = d["_source"].get("rule", {}).get("name", "Unknown")
                    det_rules[name] += 1
                det_lines = [f"SO SIGMA: {len(high_sigma)} detection(s)"]
                for rule, count in sorted(det_rules.items(), key=lambda x: -x[1]):
                    det_lines.append(f"- {rule} (x{count})")
                notify_all(
                    cfg.notifications,
                    f"[SO SIGMA] {len(high_sigma)} detection(s)",
                    "\n".join(det_lines),
                )

    state.finish_run(alerts=len(all_results), high=high_count)
    print("\n" + summary_text)
