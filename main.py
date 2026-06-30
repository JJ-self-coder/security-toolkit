#!/usr/bin/env python3
"""
Security Testing Toolkit (网络安全测试辅助工具集)
================================================
轻量化命令行工具集，覆盖端口探测、资产信息采集、批量漏洞验证全流程。

Usage:
    python main.py scan --target 192.168.1.1 --ports top20
    python main.py recon --target example.com --modules all
    python main.py verify --targets targets.txt --checks info_leak,weak_pwd
    python main.py full --target example.com --output report
    python main.py export --input results.json --output report.xlsx

仅用于授权测试环境与实训靶场。
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

# Ensure the toolkit package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (
    DEFAULT_TIMEOUT, DEFAULT_RATE, DEFAULT_WORKERS,
    PORT_PRESETS, DIR_TRAVERSAL_PATHS, INFO_LEAK_PATHS, WEAK_PASSWORDS,
)
from scanner.port_scanner import scan_ports, ScanReport
from scanner.service_fingerprint import probe_http_service
from scanner.os_fingerprint import fingerprint_os
from recon.domain_info import collect_domain_info, lookup_whois, lookup_dns, lookup_icp
from recon.ip_geo import lookup_ip_geo, batch_lookup_ips
from recon.cms_detect import detect_cms, batch_detect_cms
from recon.subdomain_enum import enumerate_subdomains
from verify.check_info_leak import check_info_leak, batch_check_info_leak
from verify.check_weak_pwd import check_web_login, check_ftp_login, batch_check_weak_pwd
from verify.check_dir_traversal import check_dir_traversal, batch_check_dir_traversal
from verify.risk_engine import VulnFinding
from output.data_processor import (
    AssetRecord, VulnRecord, FullReport,
    build_asset_record, build_full_report, report_to_dict,
)
from output.excel_exporter import export_to_excel, export_to_json, export_report
from utils.logger import setup_logger, log
from utils.helpers import parse_target, parse_port_spec, resolve_host, is_ip


# ─── Banner ────────────────────────────────────────────────────────────
BANNER: str = r"""
  ╔═══════════════════════════════════════════════╗
  ║      Security Testing Toolkit v1.0           ║
  ║      网络安全测试辅助工具集                      ║
  ║      >>> 仅用于授权测试与实训靶场 <<<          ║
  ╚═══════════════════════════════════════════════╝
"""


# ═══════════════════════════════════════════════════════════════════════
# Sub-command: scan  (端口扫描与服务识别)
# ═══════════════════════════════════════════════════════════════════════

def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the 'scan' sub-command."""
    print(BANNER)
    log.info("Mode: Port Scan & Service Fingerprinting")

    targets = _load_targets(args.target)
    all_results: Dict[str, ScanReport] = {}

    for target in targets:
        log.info("=" * 56)
        log.info("Target: %s", target)
        report = scan_ports(
            target=target,
            ports=args.ports,
            timeout=args.timeout,
            rate=args.rate,
            workers=args.workers,
        )
        all_results[target] = report

        # Print summary
        print(f"\n{'─' * 50}")
        print(f"  Target:        {target}")
        print(f"  Scanned ports: {report.total_scanned}")
        print(f"  Open ports:    {len(report.open_ports)}")
        print(f"  Duration:      {report.scan_duration:.1f}s")
        if report.open_ports:
            print(f"\n  {'PORT':<8} {'SERVICE':<24} {'VERSION':<16} {'OS'}")
            print(f"  {'─' * 8} {'─' * 24} {'─' * 16} {'─' * 10}")
            for p in report.open_ports:
                print(f"  {p.port:<8} {p.service_name:<24} {p.version:<16} {p.os_hint}")
        print(f"{'─' * 50}")

        # OS fingerprinting
        if args.os_detect and report.open_ports:
            log.info("Running OS fingerprinting on %s...", target)
            open_port_nums = [p.port for p in report.open_ports]
            os_results = fingerprint_os(target, open_port_nums, args.timeout)
            if os_results:
                print(f"\n  OS Fingerprinting Results:")
                for fp in os_results:
                    print(f"    {fp.os_name} (confidence: {fp.confidence:.0%}) — {fp.source}")
                    if fp.os_version:
                        print(f"      Version: {fp.os_version}")

        # HTTP service fingerprinting
        if args.http_fingerprint:
            for p in report.open_ports:
                if p.port in (80, 443, 8080, 8443, 8000, 8888, 9443):
                    use_ssl = p.port in (443, 8443, 9443)
                    svc_info = probe_http_service(target, p.port, use_ssl=use_ssl)
                    if svc_info:
                        print(f"\n  HTTP Service @ {target}:{p.port}")
                        print(f"    Server:    {svc_info.web_server}")
                        print(f"    Tech:      {', '.join(svc_info.web_tech)}")
                        print(f"    Title:     {svc_info.title}")
                        print(f"    OS:        {svc_info.os_type}")

    # Save intermediate result
    if args.output:
        _save_scan_results(all_results, args.output)

    return 0


# ═══════════════════════════════════════════════════════════════════════
# Sub-command: recon  (资产信息采集)
# ═══════════════════════════════════════════════════════════════════════

def cmd_recon(args: argparse.Namespace) -> int:
    """Execute the 'recon' sub-command."""
    print(BANNER)
    log.info("Mode: Asset Reconnaissance")

    targets = _load_targets(args.target)
    modules = _parse_modules(args.modules)
    all_results: dict = {}

    for target in targets:
        log.info("=" * 56)
        log.info("Target: %s", target)
        result: dict = {"target": target}

        # WHOIS
        if "whois" in modules or "all" in modules:
            result["whois"] = lookup_whois(target)
            if result["whois"] and result["whois"].registrar:
                log.info("  WHOIS: %s | Created: %s | Expires: %s",
                         result["whois"].registrar,
                         result["whois"].creation_date,
                         result["whois"].expiration_date)

        # DNS
        if "dns" in modules or "all" in modules:
            result["dns"] = lookup_dns(target)
            dns = result["dns"]
            if dns.a_records:
                log.info("  DNS A: %s", ", ".join(dns.a_records))
            if dns.mx_records:
                log.info("  DNS MX: %s", ", ".join(dns.mx_records[:3]))

        # ICP Filing
        if "icp" in modules or "all" in modules:
            result["icp"] = lookup_icp(target)
            if result["icp"] and result["icp"].is_found:
                log.info("  ICP: %s — %s", result["icp"].icp_number, result["icp"].company_name)

        # IP Geolocation
        if "geo" in modules or "all" in modules:
            ip = resolve_host(target)
            if ip:
                result["geo"] = lookup_ip_geo(ip)
                if result["geo"]:
                    log.info("  Geo: %s, %s, %s [ISP: %s]",
                             result["geo"].country,
                             result["geo"].region,
                             result["geo"].city,
                             result["geo"].isp)

        # CMS Detection
        if "cms" in modules or "all" in modules:
            result["cms"] = detect_cms(target)
            if result["cms"] and result["cms"].cms_name:
                log.info("  CMS: %s (%s) confidence=%.0f%%",
                         result["cms"].cms_name,
                         result["cms"].category,
                         result["cms"].confidence * 100)
                if result["cms"].technologies:
                    log.info("  Tech Stack: %s", ", ".join(result["cms"].technologies))

        # Subdomain Enumeration
        if "subdomain" in modules or "all" in modules:
            result["subdomains"] = enumerate_subdomains(target)
            if result["subdomains"]:
                subs = result["subdomains"]
                log.info("  Subdomains: %d discovered (%s)", subs.total_found, subs.source)
                if subs.total_found > 0 and subs.total_found <= 30:
                    for sub in subs.subdomains:
                        ips = subs.resolved_ips.get(sub, [])
                        ip_str = ", ".join(ips) if ips else "unresolved"
                        log.info("    - %s → %s", sub, ip_str)

        all_results[target] = result

    # Save
    if args.output:
        output_path = args.output
        if not output_path.endswith(".json"):
            output_path += ".json"
        serializable = {}
        for t, r in all_results.items():
            serializable[t] = _make_serializable(r)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(serializable, fh, ensure_ascii=False, indent=2)
        log.info("Recon results saved: %s", output_path)

    return 0


# ═══════════════════════════════════════════════════════════════════════
# Sub-command: verify  (漏洞批量验证)
# ═══════════════════════════════════════════════════════════════════════

def cmd_verify(args: argparse.Namespace) -> int:
    """Execute the 'verify' sub-command."""
    print(BANNER)
    log.info("Mode: Vulnerability Verification")

    targets = _load_targets(args.targets)
    checks = _parse_checks(args.checks)
    all_findings: List[VulnFinding] = []

    log.info("Targets: %d | Checks: %s", len(targets), ", ".join(checks))

    for check in checks:
        log.info("─" * 50)
        log.info("Running check: %s", check)

        if check == "info_leak":
            results = batch_check_info_leak(targets)
            for t_findings in results.values():
                all_findings.extend(t_findings)

        elif check == "weak_pwd":
            # Build target definitions for weak password checks
            weak_targets = []
            for t in targets:
                url = f"http://{t}" if not t.startswith("http") else t
                weak_targets.append({
                    "type": "web",
                    "host": t,
                    "target": url,
                    "port": 80,
                    "login_path": args.login_path or "/login",
                    "username_field": args.username_field or "username",
                    "password_field": args.password_field or "password",
                })
            findings = batch_check_weak_pwd(weak_targets, workers=args.workers)
            all_findings.extend(findings)

        elif check == "dir_traversal":
            results = batch_check_dir_traversal(targets)
            for t_findings in results.values():
                all_findings.extend(t_findings)

    # Print summary
    print(f"\n{'═' * 56}")
    print(f"  漏洞验证结果汇总")
    print(f"{'═' * 56}")
    if not all_findings:
        print("  未发现漏洞。")
    else:
        level_order = {"严重": 1, "高危": 2, "中危": 3, "低危": 4, "信息": 5}
        all_findings.sort(key=lambda f: level_order.get(f.risk_level.value, 99))

        for finding in all_findings:
            risk_tag = f"[{finding.risk_level.value}]"
            print(f"  {risk_tag:<8} {finding.name}")
            print(f"             Target: {finding.target}")
            print(f"             CVSS:   {finding.cvss_score:.1f}")
            if finding.evidence:
                evidence_short = finding.evidence[:100].replace('\n', ' ')
                print(f"             Evidence: {evidence_short}")
            print()

    # Save results
    if args.output:
        output_path = args.output
        if not output_path.endswith(".json"):
            output_path += ".json"
        serializable = [_make_serializable(f) for f in all_findings]
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(serializable, fh, ensure_ascii=False, indent=2)
        log.info("Vulnerability results saved: %s", output_path)

    log.info("Total vulnerabilities found: %d", len(all_findings))
    return 0


# ═══════════════════════════════════════════════════════════════════════
# Sub-command: full  (全流程测试)
# ═══════════════════════════════════════════════════════════════════════

def cmd_full(args: argparse.Namespace) -> int:
    """Execute the 'full' sub-command — complete assessment pipeline."""
    print(BANNER)
    log.info("Mode: Full Assessment Pipeline")
    start_time = time.monotonic()

    targets = _load_targets(args.target)
    log.info("Targets: %d", len(targets))

    # Phase 1: Port Scan
    log.info("\n" + "═" * 56)
    log.info("Phase 1/4: Port Scanning & Service Fingerprinting")
    log.info("═" * 56)
    scan_results: Dict[str, ScanReport] = {}
    for target in targets:
        log.info("Scanning: %s (ports: %s)", target, args.ports)
        report = scan_ports(
            target=target,
            ports=args.ports,
            timeout=args.timeout,
            rate=args.rate,
            workers=args.workers,
        )
        scan_results[target] = report

    # Phase 2: Asset Reconnaissance
    log.info("\n" + "═" * 56)
    log.info("Phase 2/4: Asset Information Collection")
    log.info("═" * 56)
    domain_info: Dict[str, dict] = {}
    geo_info: dict = {}
    cms_results: dict = {}
    subdomain_results: dict = {}

    for target in targets:
        domain_info[target] = collect_domain_info(target)
        cms_results[target] = detect_cms(target)

        # Only enumerate subdomains for domain targets
        if not is_ip(target):
            subdomain_results[target] = enumerate_subdomains(target)

        # IP geolocation
        ip = resolve_host(target)
        if ip:
            geo_info[target] = lookup_ip_geo(ip)

    # Phase 3: Vulnerability Verification
    log.info("\n" + "═" * 56)
    log.info("Phase 3/4: Vulnerability Verification")
    log.info("═" * 56)
    all_findings: List[VulnFinding] = []

    if "info_leak" in _parse_checks(args.checks):
        leak_results = batch_check_info_leak(targets, workers=args.workers)
        for findings in leak_results.values():
            all_findings.extend(findings)

    if "weak_pwd" in _parse_checks(args.checks):
        web_targets = []
        for t in targets:
            web_targets.append({"type": "web", "host": t, "target": f"http://{t}",
                                "port": 80, "login_path": "/login"})
        wp_findings = batch_check_weak_pwd(web_targets, workers=args.workers)
        all_findings.extend(wp_findings)

    if "dir_traversal" in _parse_checks(args.checks):
        dt_results = batch_check_dir_traversal(targets, workers=args.workers)
        for findings in dt_results.values():
            all_findings.extend(findings)

    # Phase 4: Report Generation
    log.info("\n" + "═" * 56)
    log.info("Phase 4/4: Report Generation")
    log.info("═" * 56)

    report = build_full_report(
        targets=targets,
        scan_results=scan_results,
        domain_info=domain_info,
        geo_info=geo_info,
        cms_results=cms_results,
        subdomain_results=subdomain_results,
        vuln_findings=all_findings,
    )

    output_base = args.output or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    formats = _parse_export_formats(args.format)
    export_paths = export_report(report, output_base, formats=formats)

    # Print final summary
    elapsed = time.monotonic() - start_time
    print(f"\n{'═' * 56}")
    print(f"  全流程测试完成")
    print(f"{'═' * 56}")
    for k, v in report.summary.items():
        if isinstance(v, dict):
            parts = ", ".join(f"{lk}: {lv}" for lk, lv in v.items())
            print(f"  {k}: {parts}")
        else:
            print(f"  {k}: {v}")
    print(f"  总耗时: {elapsed:.1f}s")
    print(f"\n  报告文件:")
    for fmt, path in export_paths.items():
        print(f"    [{fmt}] {path}")
    print(f"{'═' * 56}")

    return 0


# ═══════════════════════════════════════════════════════════════════════
# Sub-command: export  (结果导出)
# ═══════════════════════════════════════════════════════════════════════

def cmd_export(args: argparse.Namespace) -> int:
    """Execute the 'export' sub-command — convert JSON results to Excel."""
    print(BANNER)
    log.info("Mode: Export Results")

    input_path = args.input
    if not os.path.exists(input_path):
        log.error("Input file not found: %s", input_path)
        return 1

    with open(input_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Determine format based on input structure
    if "report_title" in data and "assets" in data:
        # Full report JSON
        from output.data_processor import FullReport
        report = _dict_to_full_report(data)
    elif isinstance(data, list) and len(data) > 0 and "vuln_type" in data[0]:
        # Vulnerability findings only
        from output.data_processor import FullReport, build_vuln_record
        from verify.risk_engine import VulnFinding
        report = FullReport(
            generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        for item in data:
            f = VulnFinding(**{k: v for k, v in item.items() if k in VulnFinding.__dataclass_fields__})
            report.vulnerabilities.append(build_vuln_record(f))
    else:
        # Assume it's a scan result dict
        log.warning("Unrecognized input format — attempting generic export")
        report = FullReport(
            generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

    output_path = args.output or input_path.replace(".json", "")
    formats = _parse_export_formats(args.format)
    export_paths = export_report(report, output_path, formats=formats)

    for fmt, path in export_paths.items():
        log.info("Exported [%s]: %s", fmt, path)

    return 0


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _load_targets(target_arg: str) -> List[str]:
    """Load targets from argument or file.

    If target_arg is a file path (ends with .txt), read targets line by line.
    Otherwise, treat as a single target or comma-separated list.
    """
    if os.path.isfile(target_arg):
        with open(target_arg, "r", encoding="utf-8") as fh:
            targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        log.info("Loaded %d targets from file: %s", len(targets), target_arg)
        return targets

    # Comma-separated list
    return [t.strip() for t in target_arg.split(",") if t.strip()]


def _parse_modules(modules_arg: str) -> List[str]:
    """Parse the --modules argument into a list of module names."""
    valid = {"whois", "dns", "icp", "geo", "cms", "subdomain", "all"}
    modules = [m.strip().lower() for m in modules_arg.split(",")]
    result = [m for m in modules if m in valid]
    if "all" in result:
        return ["all"]
    return result


def _parse_checks(checks_arg: str) -> List[str]:
    """Parse the --checks argument into a list of check names."""
    valid = {"info_leak", "weak_pwd", "dir_traversal", "all"}
    checks = [c.strip().lower() for c in checks_arg.split(",")]
    result = [c for c in checks if c in valid]
    if "all" in result:
        return list(valid - {"all"})
    return result


def _parse_export_formats(format_arg: str) -> List[str]:
    """Parse the --format argument into export format list."""
    if not format_arg:
        return ["excel", "json"]
    formats = [f.strip().lower() for f in format_arg.split(",")]
    valid = {"excel", "json"}
    return [f for f in formats if f in valid]


def _save_scan_results(results: Dict[str, ScanReport], output_path: str) -> None:
    """Save scan results to JSON."""
    if not output_path.endswith(".json"):
        output_path += ".json"
    serializable = {}
    for target, report in results.items():
        serializable[target] = {
            "target": report.target,
            "total_scanned": report.total_scanned,
            "scan_duration": report.scan_duration,
            "open_ports": [
                {
                    "port": p.port,
                    "service": p.service_name,
                    "version": p.version,
                    "banner": p.banner[:200] if p.banner else "",
                    "os_hint": p.os_hint,
                }
                for p in report.open_ports
            ],
        }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(serializable, fh, ensure_ascii=False, indent=2)
    log.info("Scan results saved: %s", output_path)


def _make_serializable(obj) -> dict:
    """Convert a dataclass instance to a JSON-serializable dict."""
    if hasattr(obj, "__dataclass_fields__"):
        result = {}
        for field_name in obj.__dataclass_fields__:
            value = getattr(obj, field_name)
            if hasattr(value, "__dataclass_fields__"):
                value = _make_serializable(value)
            elif isinstance(value, list):
                value = [
                    _make_serializable(v) if hasattr(v, "__dataclass_fields__") else v
                    for v in value
                ]
            elif isinstance(value, dict):
                value = {
                    k: _make_serializable(v) if hasattr(v, "__dataclass_fields__") else v
                    for k, v in value.items()
                }
            result[field_name] = value
        return result
    return obj


def _dict_to_full_report(data: dict) -> FullReport:
    """Reconstruct a FullReport from a serialized dict."""
    from output.data_processor import FullReport, AssetRecord, VulnRecord

    report = FullReport(
        report_title=data.get("report_title", "网络安全测试报告"),
        generation_time=data.get("generation_time", ""),
        targets=data.get("targets", []),
        summary=data.get("summary", {}),
    )
    for a in data.get("assets", []):
        report.assets.append(AssetRecord(**{k: v for k, v in a.items() if k in AssetRecord.__dataclass_fields__}))
    for v in data.get("vulnerabilities", []):
        report.vulnerabilities.append(VulnRecord(**{k: v for k, v in v.items() if k in VulnRecord.__dataclass_fields__}))
    return report


# ═══════════════════════════════════════════════════════════════════════
# CLI Definition
# ═══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the toolkit."""
    parser = argparse.ArgumentParser(
        description="Security Testing Toolkit — 网络安全测试辅助工具集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan --target 192.168.1.1 --ports top20
  python main.py scan --target targets.txt --ports 1-1000 --rate 50
  python main.py recon --target example.com --modules all
  python main.py recon --target example.com --modules whois,dns,cms
  python main.py verify --targets targets.txt --checks all
  python main.py verify --targets 192.168.1.1 --checks info_leak
  python main.py full --target example.com --ports top100 --output report
  python main.py export --input results.json --output report.xlsx

Note: This tool is for AUTHORIZED testing and training environments ONLY.
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ──────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Port scanning & service fingerprinting")
    scan_parser.add_argument("--target", "-t", required=True,
                             help="Target IP, hostname, comma-separated list, or file path (.txt)")
    scan_parser.add_argument("--ports", "-p", default="top1000",
                             help="Port specification: top20/top1000/web/database/all, range (1-1000), list (80,443)")
    scan_parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                             help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    scan_parser.add_argument("--rate", type=int, default=DEFAULT_RATE,
                             help=f"Max connections per second (default: {DEFAULT_RATE})")
    scan_parser.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS,
                             help=f"Concurrent worker threads (default: {DEFAULT_WORKERS})")
    scan_parser.add_argument("--os-detect", action="store_true", default=True,
                             help="Enable OS fingerprinting (default: True)")
    scan_parser.add_argument("--http-fingerprint", action="store_true", default=True,
                             help="Enable HTTP service probing (default: True)")
    scan_parser.add_argument("--output", "-o", default=None,
                             help="Save results to JSON file")
    scan_parser.set_defaults(func=cmd_scan)

    # ── recon ─────────────────────────────────────────────────────────
    recon_parser = subparsers.add_parser("recon", help="Asset information & reconnaissance")
    recon_parser.add_argument("--target", "-t", required=True,
                              help="Target domain, IP, comma-separated list, or file path")
    recon_parser.add_argument("--modules", "-m", default="all",
                              help="Modules: whois,dns,icp,geo,cms,subdomain,all (default: all)")
    recon_parser.add_argument("--output", "-o", default=None,
                              help="Save results to JSON file")
    recon_parser.set_defaults(func=cmd_recon)

    # ── verify ────────────────────────────────────────────────────────
    verify_parser = subparsers.add_parser("verify", help="Vulnerability verification")
    verify_parser.add_argument("--targets", "-t", required=True,
                               help="Target URL(s), comma-separated list, or file path")
    verify_parser.add_argument("--checks", "-c", default="all",
                               help="Checks: info_leak,weak_pwd,dir_traversal,all (default: all)")
    verify_parser.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS,
                               help=f"Concurrent workers (default: {DEFAULT_WORKERS})")
    verify_parser.add_argument("--login-path", default="/login",
                               help="Login page path for weak password check (default: /login)")
    verify_parser.add_argument("--username-field", default="username",
                               help="Username form field name (default: username)")
    verify_parser.add_argument("--password-field", default="password",
                               help="Password form field name (default: password)")
    verify_parser.add_argument("--output", "-o", default=None,
                               help="Save results to JSON file")
    verify_parser.set_defaults(func=cmd_verify)

    # ── full ──────────────────────────────────────────────────────────
    full_parser = subparsers.add_parser("full", help="Full assessment pipeline (scan + recon + verify + export)")
    full_parser.add_argument("--target", "-t", required=True,
                             help="Target IP, domain, comma-separated list, or file path")
    full_parser.add_argument("--ports", "-p", default="top1000",
                             help="Port specification (default: top1000)")
    full_parser.add_argument("--checks", "-c", default="all",
                             help="Vulnerability checks (default: all)")
    full_parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                             help=f"Socket timeout (default: {DEFAULT_TIMEOUT})")
    full_parser.add_argument("--rate", type=int, default=DEFAULT_RATE,
                             help=f"Scan rate (default: {DEFAULT_RATE})")
    full_parser.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS,
                             help=f"Concurrent workers (default: {DEFAULT_WORKERS})")
    full_parser.add_argument("--output", "-o", default=None,
                             help="Output report base path (without extension)")
    full_parser.add_argument("--format", "-f", default="excel,json",
                             help="Export formats: excel,json (default: excel,json)")
    full_parser.set_defaults(func=cmd_full)

    # ── export ────────────────────────────────────────────────────────
    export_parser = subparsers.add_parser("export", help="Export JSON results to Excel/other formats")
    export_parser.add_argument("--input", "-i", required=True,
                               help="Input JSON file path")
    export_parser.add_argument("--output", "-o", default=None,
                               help="Output file path (without extension)")
    export_parser.add_argument("--format", "-f", default="excel,json",
                               help="Export formats: excel,json (default: both)")
    export_parser.set_defaults(func=cmd_export)

    return parser


# ═══════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════

def main() -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Configure logging level
    verbose = getattr(args, "verbose", False)
    if verbose:
        setup_logger(level=10)  # DEBUG

    try:
        return args.func(args)
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        return 130
    except Exception as exc:
        log.error("Fatal error: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
