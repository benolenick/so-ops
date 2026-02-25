"""Daily health check: collect metrics, generate LLM briefing, email report."""

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


def _is_external(ip: str, internal_prefixes: list[str]) -> bool:
    if not ip or ip == "?":
        return False
    # Exclude broadcast, multicast (224-239), link-local (169.254), and IPv6 non-routable
    if ip in ("255.255.255.255", "0.0.0.0"):
        return False
    if ip.startswith(("224.", "225.", "226.", "227.", "228.", "229.",
                      "230.", "231.", "232.", "233.", "234.", "235.",
                      "236.", "237.", "238.", "239.", "169.254.",
                      "fe80:", "ff00:", "ff01:", "ff02:", "ff05:",
                      "ff08:", "ff0e:", "::1")):
        return False
    return not any(ip.startswith(p) for p in internal_prefixes)


def _format_bytes(b: float) -> str:
    if b < 0:
        return "N/A"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _get_suricata_summary(es: SOElasticClient, index: str, log) -> dict | None:
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "total": {"value_count": {"field": "@timestamp"}},
            "by_severity": {"terms": {"field": "rule.severity", "size": 10}},
            "by_name": {"terms": {"field": "rule.name", "size": 30}},
            "by_src": {"terms": {"field": "source.ip", "size": 20}},
            "by_dst": {"terms": {"field": "destination.ip", "size": 20}},
            "by_hour": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour"}},
        },
    }
    try:
        return es.search(index, query)
    except Exception as exc:
        log.warning("Suricata query failed: %s", exc)
        return None


def _get_zeek_summary(es: SOElasticClient, index: str, log) -> dict | None:
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "total": {"value_count": {"field": "@timestamp"}},
            "by_proto": {"terms": {"field": "network.transport", "size": 10}},
            "by_service": {"terms": {"field": "network.protocol", "size": 20}},
            "top_talkers_src": {"terms": {"field": "source.ip", "size": 15}},
            "top_talkers_dst": {"terms": {"field": "destination.ip", "size": 15}},
            "top_dst_ports": {"terms": {"field": "destination.port", "size": 20}},
            "bytes_in": {"sum": {"field": "source.bytes"}},
            "bytes_out": {"sum": {"field": "destination.bytes"}},
            "orig_bytes": {"sum": {"field": "zeek.connection.orig_bytes"}},
            "resp_bytes": {"sum": {"field": "zeek.connection.resp_bytes"}},
            "by_hour": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour"}},
        },
    }
    try:
        return es.search(index, query)
    except Exception as exc:
        log.warning("Zeek query failed: %s", exc)
        return None


def _get_detection_alerts(es: SOElasticClient, index: str, log) -> list:
    query = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
    }
    try:
        result = es.search(index, query)
        return result.get("hits", {}).get("hits", [])
    except Exception as exc:
        log.warning("Detection alerts query failed: %s", exc)
        return []


def _get_syslog_errors(es: SOElasticClient, index: str, log) -> int:
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                "should": [
                    {"match_phrase": {"message": "error"}},
                    {"match_phrase": {"message": "failed"}},
                    {"match_phrase": {"message": "critical"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {"total": {"value_count": {"field": "@timestamp"}}},
    }
    try:
        result = es.search(index, query)
        return result.get("hits", {}).get("total", {}).get("value", 0)
    except Exception as exc:
        log.warning("Syslog query failed: %s", exc)
        return -1


def _get_data_stream_health(es: SOElasticClient, pattern: str, log) -> list:
    try:
        streams_raw = es.get_data_streams(pattern)
        streams = []
        for ds in streams_raw:
            name = ds["name"]
            try:
                recent_count = es.count(name, {"query": {"range": {"@timestamp": {"gte": "now-1h"}}}})
            except Exception:
                recent_count = -1
            try:
                total_count = es.count(name)
            except Exception:
                total_count = -1
            streams.append({
                "name": name,
                "status": ds.get("status", "unknown"),
                "recent_1h": recent_count,
                "total": total_count,
            })
        return streams
    except Exception as exc:
        log.warning("Data stream health check failed: %s", exc)
        return []


def _get_triage_summary_24h(triage_jsonl: Path) -> dict | None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    verdicts: dict[str, int] = defaultdict(int)
    rules_by_verdict: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    total = 0

    if not triage_jsonl.exists():
        return None

    for line in open(triage_jsonl):
        try:
            entry = json.loads(line)
            if entry.get("triaged_at", "") >= cutoff:
                v = entry["verdict"]
                verdicts[v] += 1
                rules_by_verdict[v][entry["rule_name"]] += 1
                total += 1
        except (json.JSONDecodeError, KeyError):
            continue

    return {
        "total": total,
        "verdicts": dict(verdicts),
        "rules_by_verdict": {k: dict(v) for k, v in rules_by_verdict.items()},
    }


def _get_external_ips(es: SOElasticClient, index: str, internal_prefixes: list[str], log) -> list:
    query = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "ext_dst": {"terms": {"field": "destination.ip", "size": 50}},
            "ext_src": {"terms": {"field": "source.ip", "size": 50}},
        },
    }
    try:
        result = es.search(index, query)
        ext_ips = set()
        for agg_key in ("ext_dst", "ext_src"):
            for bucket in result.get("aggregations", {}).get(agg_key, {}).get("buckets", []):
                ip = bucket["key"]
                if _is_external(ip, internal_prefixes):
                    ext_ips.add((ip, bucket["doc_count"]))
        return sorted(ext_ips, key=lambda x: -x[1])[:20]
    except Exception as exc:
        log.warning("External IP query failed: %s", exc)
        return []


def _build_report(suricata, zeek, detections, syslog_errors, streams,
                  triage, ext_ips, internal_prefixes) -> str:
    now = datetime.now(timezone.utc)
    lines = [
        "# Daily Network & Event Health Report",
        f"**Date:** {now.strftime('%Y-%m-%d %H:%M UTC')}",
        "**Period:** Last 24 hours",
        "",
    ]

    # 1. Data Pipeline Health
    lines.append("## 1. Data Pipeline Health")
    if streams:
        lines.append("| Data Stream | Status | Docs (1h) | Total Docs |")
        lines.append("|-------------|--------|-----------|------------|")
        for s in streams:
            recent = str(s["recent_1h"]) if s["recent_1h"] >= 0 else "ERR"
            total = f"{s['total']:,}" if s["total"] >= 0 else "ERR"
            status_icon = "OK" if s["status"] == "GREEN" else s["status"]
            lines.append(f"| {s['name']} | {status_icon} | {recent} | {total} |")
        stale = [s for s in streams if s["recent_1h"] == 0]
        if stale:
            lines.append("")
            lines.append(f"**Warning:** {len(stale)} stream(s) with 0 docs in the last hour: "
                         f"{', '.join(s['name'] for s in stale)}")
    else:
        lines.append("*Data stream health check failed*")
    lines.append("")

    # 2. Suricata Alerts
    lines.append("## 2. IDS Alerts (Suricata)")
    if suricata:
        aggs = suricata.get("aggregations", {})
        total_alerts = suricata.get("hits", {}).get("total", {}).get("value", 0)
        lines.append(f"**Total alerts (24h):** {total_alerts:,}")
        lines.append("")

        sev_buckets = aggs.get("by_severity", {}).get("buckets", [])
        if sev_buckets:
            sev_labels = {1: "High", 2: "Medium", 3: "Low"}
            lines.append("**By severity:**")
            for b in sorted(sev_buckets, key=lambda x: x["key"]):
                label = sev_labels.get(b["key"], str(b["key"]))
                lines.append(f"- Severity {b['key']} ({label}): {b['doc_count']:,}")
            lines.append("")

        name_buckets = aggs.get("by_name", {}).get("buckets", [])
        if name_buckets:
            lines.append("**Top alert signatures:**")
            for b in name_buckets[:15]:
                lines.append(f"- {b['key']}: {b['doc_count']:,}")
            lines.append("")

        src_buckets = aggs.get("by_src", {}).get("buckets", [])
        if src_buckets:
            lines.append("**Top source IPs:**")
            for b in src_buckets[:10]:
                ext = " (EXTERNAL)" if _is_external(b["key"], internal_prefixes) else ""
                lines.append(f"- {b['key']}{ext}: {b['doc_count']:,}")
            lines.append("")

        hour_buckets = aggs.get("by_hour", {}).get("buckets", [])
        if hour_buckets:
            max_count = max(b["doc_count"] for b in hour_buckets) if hour_buckets else 1
            lines.append("**Alert volume by hour:**")
            lines.append("```")
            for b in hour_buckets:
                ts = b["key_as_string"][:16] if "key_as_string" in b else str(b["key"])
                bar_len = int(b["doc_count"] / max(max_count, 1) * 40)
                bar = "#" * bar_len
                lines.append(f"  {ts} | {bar} {b['doc_count']}")
            lines.append("```")
            lines.append("")
    else:
        lines.append("*Suricata query failed*")
        lines.append("")

    # 3. Triage Summary
    lines.append("## 3. Alert Triage Summary (AI-processed)")
    if triage and triage["total"] > 0:
        lines.append(f"**Total triaged (24h):** {triage['total']:,}")
        for v in ("HIGH", "MEDIUM", "LOW", "NOISE"):
            count = triage["verdicts"].get(v, 0)
            pct = count / triage["total"] * 100 if triage["total"] else 0
            lines.append(f"- **{v}**: {count} ({pct:.1f}%)")
            if v in ("HIGH", "MEDIUM") and v in triage["rules_by_verdict"]:
                for rule, cnt in sorted(triage["rules_by_verdict"][v].items(), key=lambda x: -x[1]):
                    lines.append(f"  - {rule}: {cnt}")
        lines.append("")
    else:
        lines.append("*No triage data available for this period*")
        lines.append("")

    # 4. Detection Alerts (Sigma)
    lines.append("## 4. Detection Alerts (Sigma)")
    if detections:
        lines.append(f"**Total detections (24h):** {len(detections)}")
        det_by_rule: dict[str, int] = defaultdict(int)
        for d in detections:
            rule_name = d["_source"].get("rule", {}).get("name", "Unknown")
            det_by_rule[rule_name] += 1
        for rule, count in sorted(det_by_rule.items(), key=lambda x: -x[1]):
            sev = "?"
            for d in detections:
                if d["_source"].get("rule", {}).get("name") == rule:
                    sev = d["_source"].get("sigma_level", "?")
                    break
            lines.append(f"- **{rule}** ({sev}): {count}")
        lines.append("")
    else:
        lines.append("*No Sigma detection alerts in the last 24h*")
        lines.append("")

    # 5. Network Traffic
    lines.append("## 5. Network Traffic (Zeek)")
    if zeek:
        aggs = zeek.get("aggregations", {})
        total_conns = zeek.get("hits", {}).get("total", {}).get("value", 0)
        bytes_in = aggs.get("bytes_in", {}).get("value", 0) or 0
        bytes_out = aggs.get("bytes_out", {}).get("value", 0) or 0
        # Fall back to Zeek-native field names if ECS fields are empty
        if bytes_in == 0 and bytes_out == 0:
            bytes_in = aggs.get("orig_bytes", {}).get("value", 0) or 0
            bytes_out = aggs.get("resp_bytes", {}).get("value", 0) or 0

        lines.append(f"**Total connections (24h):** {total_conns:,}")
        lines.append(f"**Data transferred:** {_format_bytes(bytes_in)} in / {_format_bytes(bytes_out)} out")
        lines.append("")

        proto_buckets = aggs.get("by_proto", {}).get("buckets", [])
        if proto_buckets:
            lines.append("**By transport protocol:**")
            for b in proto_buckets:
                lines.append(f"- {b['key']}: {b['doc_count']:,}")
            lines.append("")

        svc_buckets = aggs.get("by_service", {}).get("buckets", [])
        if svc_buckets:
            lines.append("**Top application protocols:**")
            for b in svc_buckets[:10]:
                lines.append(f"- {b['key']}: {b['doc_count']:,}")
            lines.append("")

        port_buckets = aggs.get("top_dst_ports", {}).get("buckets", [])
        if port_buckets:
            lines.append("**Top destination ports:**")
            for b in port_buckets[:10]:
                lines.append(f"- :{b['key']}: {b['doc_count']:,}")
            lines.append("")

        src_buckets = aggs.get("top_talkers_src", {}).get("buckets", [])
        if src_buckets:
            lines.append("**Top talkers (source):**")
            for b in src_buckets[:10]:
                ext = " (EXT)" if _is_external(b["key"], internal_prefixes) else ""
                lines.append(f"- {b['key']}{ext}: {b['doc_count']:,}")
            lines.append("")
    else:
        lines.append("*Zeek query failed*")
        lines.append("")

    # 6. External IPs
    lines.append("## 6. External IPs Seen")
    if ext_ips:
        lines.append(f"**Top {len(ext_ips)} external IPs by connection count:**")
        for ip, count in ext_ips:
            lines.append(f"- {ip}: {count:,}")
        lines.append("")
    else:
        lines.append("*No external IPs found or query failed*")
        lines.append("")

    # 7. System Health
    lines.append("## 7. System Health")
    if syslog_errors >= 0:
        lines.append(f"**Syslog errors/failures (24h):** {syslog_errors:,}")
        if syslog_errors > 100:
            lines.append("**Note:** High number of syslog errors — worth investigating")
    else:
        lines.append("*Syslog query failed*")
    lines.append("")

    return "\n".join(lines)


def _build_zone_context(zones) -> str:
    """Build network context string from configured zones."""
    if not zones:
        return ""
    lines = ["Network zones:"]
    for z in zones:
        lines.append(f"- {z.cidr} = {z.name} ({z.description})")
    return "\n".join(lines) + "\n\n"


def _generate_llm_briefing(raw_report: str, llm: OllamaClient,
                           temperature: float, zones) -> str:
    zone_context = _build_zone_context(zones)

    prompt = f"""You are a Security Operations Center analyst producing a morning briefing for the network administrator of a home lab / small business network.

{zone_context}Below is the raw health report data from the last 24 hours. Write a concise, actionable morning briefing that:

1. **Overall Status** - One line: is the network healthy, degraded, or concerning? Use a simple rating (Green/Yellow/Red).
2. **Key Findings** - 3-5 bullet points of the most important things to know. Focus on:
   - Anything abnormal or concerning
   - Security-relevant findings (attacks, scans, vulnerable services)
   - Data pipeline issues (streams not ingesting)
   - Notable traffic patterns
3. **Action Items** - Specific things the admin should do today (if any). Be concrete.
4. **Noise Report** - One line summarizing what was auto-cleared and doesn't need attention.

Keep it brief and scannable. No fluff. The admin is busy and wants the key points in 30 seconds.

--- RAW REPORT DATA ---
{raw_report}
--- END RAW DATA ---

Write the briefing now:"""

    return llm.generate(prompt, temperature=temperature, max_tokens=4096, timeout=180)


def run_health(cfg: Config):
    """Main health check entry point."""
    data_dir = cfg.paths.data_dir
    log_dir = data_dir / "logs"
    state_dir = data_dir / "state"
    output_dir = data_dir / "output" / "health"
    triage_jsonl = log_dir / "triage.jsonl"

    log = setup_logging("health", log_dir)
    state = ToolState("health", state_dir)
    state.start_run()

    es = SOElasticClient(cfg.elasticsearch)
    llm = OllamaClient(cfg.ollama)
    indices = cfg.elasticsearch.indices
    internal_prefixes = cfg.network.internal_prefixes
    zones = cfg.network.zones

    log.info("=" * 60)
    log.info("Daily Health Checkup starting")
    start = time.time()

    log.info("Querying Suricata alerts...")
    suricata = _get_suricata_summary(es, indices.suricata, log)

    log.info("Querying Zeek connections...")
    zeek = _get_zeek_summary(es, indices.zeek, log)

    log.info("Querying detection alerts...")
    detections = _get_detection_alerts(es, indices.detections, log)

    log.info("Checking syslog errors...")
    syslog_errors = _get_syslog_errors(es, indices.syslog, log)

    log.info("Checking data stream health...")
    streams = _get_data_stream_health(es, indices.data_streams, log)

    log.info("Loading triage summary...")
    triage = _get_triage_summary_24h(triage_jsonl)

    log.info("Querying external IPs...")
    ext_ips = _get_external_ips(es, indices.zeek, internal_prefixes, log)

    log.info("Building raw report...")
    raw_report = _build_report(suricata, zeek, detections, syslog_errors,
                               streams, triage, ext_ips, internal_prefixes)

    log.info("Generating AI briefing...")
    briefing = _generate_llm_briefing(raw_report, llm, cfg.health.llm_temperature, zones)

    now = datetime.now(timezone.utc)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / f"health_{now.strftime('%Y%m%d_%H%M%S')}.md"

    final_report = f"""# Morning Briefing — {now.strftime('%A, %B %d, %Y')}

{briefing}

---

{raw_report}
"""

    report_file.write_text(final_report)

    log.info("Sending notifications...")
    first_line = briefing.split("\n")[0][:60] if briefing else ""
    email_subject = f"SO Daily Health — {now.strftime('%A %b %d')} — {first_line}"
    notify_all(cfg.notifications, email_subject, final_report)

    elapsed = time.time() - start
    state.finish_run(report=str(report_file))
    log.info("Health report generated in %.1fs: %s", elapsed, report_file)

    print(final_report)
    return str(report_file)
