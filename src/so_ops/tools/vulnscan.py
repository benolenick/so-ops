"""Vulnerability scanning: nmap + vulners and nuclei, with LLM summary."""

from __future__ import annotations

import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from so_ops.config import Config
from so_ops.clients.ollama import OllamaClient
from so_ops.clients.notify import notify_all
from so_ops.log import setup_logging
from so_ops.state import ToolState


def _run_cmd(cmd: list[str], log, timeout: int = 3600) -> tuple[int, str, str]:
    log.info("Running: %s", " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        log.error("Command timed out after %ds", timeout)
        return -1, "", "timeout"


# ── nmap ─────────────────────────────────────────────────────────────

def _run_nmap(targets: list[str], nmap_bin: str, nmap_args: str,
              scan_dir: Path, timestamp: str, log) -> tuple[Path | None, Path | None]:
    xml_out = scan_dir / f"nmap_{timestamp}.xml"
    txt_out = scan_dir / f"nmap_{timestamp}.txt"

    cmd = [nmap_bin] + nmap_args.split()
    cmd += ["-oX", str(xml_out), "-oN", str(txt_out)]
    cmd += targets

    rc, stdout, stderr = _run_cmd(cmd, log, timeout=3600)
    if rc != 0:
        log.error("nmap failed (rc=%d): %s", rc, stderr[:500])
        return None, None

    log.info("nmap complete. XML: %s", xml_out)
    return xml_out, txt_out


def _parse_nmap_xml(xml_path: Path | None) -> tuple[list, list, list]:
    """Returns (hosts, vulns, http_targets)."""
    if not xml_path or not xml_path.exists():
        return [], [], []

    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts, vulns, http_targets = [], [], []

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_elem = host_elem.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        ports_info = []
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            port_id = port_elem.get("portid")
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "") if service_elem is not None else ""
            service_product = service_elem.get("product", "") if service_elem is not None else ""
            service_version = service_elem.get("version", "") if service_elem is not None else ""

            if service_name in ("http", "https", "http-proxy", "ssl/http"):
                scheme = ("https" if "ssl" in service_name or "https" in service_name
                          or port_id in ("443", "8443", "9443") else "http")
                http_targets.append(f"{scheme}://{ip}:{port_id}")

            port_info = {
                "port": f"{port_id}/{protocol}",
                "service": service_name,
                "product": f"{service_product} {service_version}".strip(),
            }

            for script_elem in port_elem.findall("script"):
                if script_elem.get("id") == "vulners":
                    output = script_elem.get("output", "")
                    for line in output.split("\n"):
                        line = line.strip()
                        cve_match = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.?\d*)", line)
                        if cve_match:
                            vulns.append({
                                "host": ip,
                                "hostname": hostname,
                                "port": f"{port_id}/{protocol}",
                                "service": f"{service_product} {service_version}".strip(),
                                "cve": cve_match.group(1),
                                "cvss": float(cve_match.group(2)),
                            })

            ports_info.append(port_info)

        if ports_info:
            hosts.append({"ip": ip, "hostname": hostname, "ports": ports_info})

    vulns.sort(key=lambda v: v["cvss"], reverse=True)
    return hosts, vulns, http_targets


# ── nuclei ───────────────────────────────────────────────────────────

def _run_nuclei(http_targets: list[str], nuclei_docker: str,
                nuclei_severity: str, scan_dir: Path,
                timestamp: str, log) -> Path | None:
    if not http_targets:
        log.info("No HTTP targets found for nuclei scan")
        return None

    jsonl_out = scan_dir / f"nuclei_{timestamp}.jsonl"
    txt_out = scan_dir / f"nuclei_{timestamp}.txt"
    targets_file = scan_dir / f"nuclei_targets_{timestamp}.txt"
    targets_file.write_text("\n".join(http_targets) + "\n")

    cmd = [
        "docker", "run", "--rm", "--network=host",
        "-v", f"{scan_dir}:/output",
        "-v", f"{targets_file}:/targets.txt:ro",
        nuclei_docker,
        "-l", "/targets.txt",
        "-severity", nuclei_severity,
        "-jsonl", f"/output/{jsonl_out.name}",
        "-o", f"/output/{txt_out.name}",
        "-silent", "-timeout", "10", "-retries", "1", "-rate-limit", "50",
    ]

    rc, stdout, stderr = _run_cmd(cmd, log, timeout=3600)
    targets_file.unlink(missing_ok=True)

    if rc != 0 and not jsonl_out.exists():
        log.error("nuclei failed (rc=%d): %s", rc, stderr[:500])
        return None

    log.info("nuclei complete. JSONL: %s", jsonl_out)
    return jsonl_out


def _parse_nuclei_jsonl(jsonl_path: Path | None) -> list:
    findings = []
    if not jsonl_path or not jsonl_path.exists():
        return findings

    for line in jsonl_path.read_text().strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "template_id": entry.get("template-id", ""),
                "name": entry.get("info", {}).get("name", ""),
                "severity": entry.get("info", {}).get("severity", ""),
                "host": entry.get("host", ""),
                "matched_at": entry.get("matched-at", ""),
                "description": entry.get("info", {}).get("description", "")[:200],
                "cve_id": ", ".join(entry.get("info", {}).get("classification", {}).get("cve-id", []) or []),
            })
        except json.JSONDecodeError:
            continue
    return findings


# ── Report ───────────────────────────────────────────────────────────

def _build_report(hosts: list, vulns: list, nuclei_findings: list,
                  timestamp: str, scan_types: list[str]) -> str:
    lines = [
        "# Vulnerability Scan Report",
        f"**Date:** {timestamp}",
        f"**Scanner(s):** {', '.join(scan_types)}",
        f"**Hosts discovered:** {len(hosts)}",
        "",
    ]

    if hosts:
        lines.append("## Host/Service Inventory")
        lines.append("")
        for h in hosts:
            name = f" ({h['hostname']})" if h["hostname"] else ""
            lines.append(f"### {h['ip']}{name}")
            for p in h["ports"]:
                product = f" - {p['product']}" if p["product"] else ""
                lines.append(f"  - {p['port']}: {p['service']}{product}")
            lines.append("")

    if vulns:
        critical = [v for v in vulns if v["cvss"] >= 9.0]
        high = [v for v in vulns if 7.0 <= v["cvss"] < 9.0]
        medium = [v for v in vulns if 4.0 <= v["cvss"] < 7.0]

        lines.append("## CVE Vulnerabilities (nmap/vulners)")
        lines.append(f"  - Critical (CVSS >= 9.0): {len(critical)}")
        lines.append(f"  - High (CVSS 7.0-8.9): {len(high)}")
        lines.append(f"  - Medium (CVSS 4.0-6.9): {len(medium)}")
        lines.append("")

        if critical:
            lines.append("### Critical CVEs")
            for v in critical[:20]:
                lines.append(f"  - **{v['cve']}** (CVSS {v['cvss']}) on {v['host']}:{v['port']} ({v['service']})")
            lines.append("")

        if high:
            lines.append("### High CVEs")
            for v in high[:30]:
                lines.append(f"  - {v['cve']} (CVSS {v['cvss']}) on {v['host']}:{v['port']} ({v['service']})")
            lines.append("")

    if nuclei_findings:
        lines.append("## Nuclei Findings")
        by_severity: dict[str, list] = {}
        for f in nuclei_findings:
            by_severity.setdefault(f["severity"], []).append(f)
        for sev in ("critical", "high", "medium"):
            items = by_severity.get(sev, [])
            if items:
                lines.append(f"### {sev.upper()} ({len(items)})")
                for item in items[:20]:
                    cve = f" [{item['cve_id']}]" if item["cve_id"] else ""
                    lines.append(f"  - **{item['name']}**{cve} at {item['matched_at']}")
                lines.append("")

    if not vulns and not nuclei_findings:
        lines.append("## No vulnerabilities found")
        lines.append("All scanned services appear to be up to date.")

    return "\n".join(lines)


def _generate_ai_summary(report_text: str, llm: OllamaClient) -> str | None:
    prompt = f"""You are a security analyst. Below is a vulnerability scan report from a home/small-office network.
Write a concise executive summary (5-10 bullet points) covering:
1. Overall risk posture
2. Most critical findings requiring immediate attention
3. Recommended remediation priorities
4. Any notable patterns or concerns

Be specific about which hosts and CVEs need attention. Be practical - this is a home network, not an enterprise.

--- SCAN REPORT ---
{report_text[:4000]}
--- END REPORT ---

Executive Summary:"""

    return llm.generate(prompt, temperature=0.3, max_tokens=2000, timeout=120)


# ── Entry point ──────────────────────────────────────────────────────

def run_vulnscan(cfg: Config, scan_type: str = "all"):
    """Main vulnscan entry point. scan_type: 'all', 'nmap', or 'nuclei'."""
    data_dir = cfg.paths.data_dir
    log_dir = data_dir / "logs"
    state_dir = data_dir / "state"
    scan_dir = data_dir / "output" / "vulnscan"
    scan_dir.mkdir(parents=True, exist_ok=True)

    log = setup_logging("vulnscan", log_dir)
    state = ToolState("vulnscan", state_dir)
    state.start_run()

    llm = OllamaClient(cfg.ollama)
    vs = cfg.vulnscan
    targets = vs.targets

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log.info("Starting vulnerability scan: %s", timestamp)
    log.info("Targets: %s", ", ".join(targets))

    do_nmap = scan_type in ("all", "nmap")
    do_nuclei = scan_type in ("all", "nuclei")

    hosts, vulns, http_targets, nuclei_findings = [], [], [], []
    scan_types: list[str] = []

    if do_nmap:
        log.info("=== Starting nmap scan ===")
        scan_types.append("nmap + vulners")
        xml_out, txt_out = _run_nmap(targets, vs.nmap_bin, vs.nmap_args, scan_dir, timestamp, log)
        if xml_out:
            hosts, vulns, http_targets = _parse_nmap_xml(xml_out)
            log.info("nmap found %d hosts, %d CVEs, %d HTTP targets",
                     len(hosts), len(vulns), len(http_targets))
        else:
            log.warning("nmap scan produced no output")

    if do_nuclei:
        log.info("=== Starting nuclei scan ===")
        scan_types.append("nuclei")

        if not http_targets and not do_nmap:
            log.info("No HTTP targets from nmap, running ping sweep...")
            for target in targets:
                rc, stdout, stderr = _run_cmd(
                    [vs.nmap_bin, "-sn", target, "-oG", "-"], log, timeout=120
                )
                for line in stdout.split("\n"):
                    if "Host:" in line and "Status: Up" in line:
                        ip = line.split("Host:")[1].split("(")[0].strip()
                        for port in (80, 443, 8080, 8443, 9443):
                            http_targets.append(f"http://{ip}:{port}")

        if http_targets:
            jsonl_out = _run_nuclei(http_targets, vs.nuclei_docker,
                                    vs.nuclei_severity, scan_dir, timestamp, log)
            if jsonl_out:
                nuclei_findings = _parse_nuclei_jsonl(jsonl_out)
                log.info("nuclei found %d findings", len(nuclei_findings))
        else:
            log.info("No HTTP targets to scan with nuclei")

    log.info("=== Building report ===")
    report = _build_report(hosts, vulns, nuclei_findings, timestamp, scan_types)

    report_path = scan_dir / f"report_{timestamp}.md"
    report_path.write_text(report)
    log.info("Report saved: %s", report_path)

    log.info("=== Generating AI summary ===")
    ai_summary = _generate_ai_summary(report, llm)

    if ai_summary:
        full_report = f"## AI Executive Summary\n\n{ai_summary}\n\n---\n\n{report}"
    else:
        log.warning("AI summary generation failed, using raw report")
        full_report = report

    full_report_path = scan_dir / f"full_report_{timestamp}.md"
    full_report_path.write_text(full_report)
    log.info("Full report saved: %s", full_report_path)

    log.info("=== Sending notifications ===")
    vuln_count = len(vulns) + len(nuclei_findings)
    subject = f"[VulnScan] {timestamp} - {len(hosts)} hosts, {vuln_count} findings"
    notify_all(cfg.notifications, subject, full_report)

    state.finish_run(hosts=len(hosts), cves=len(vulns), nuclei=len(nuclei_findings))

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Hosts: {len(hosts)}")
    print(f"CVEs (nmap): {len(vulns)}")
    print(f"Findings (nuclei): {len(nuclei_findings)}")
    print(f"Report: {full_report_path}")
