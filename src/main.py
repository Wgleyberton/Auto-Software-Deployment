import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml
from dotenv import load_dotenv

# Load .env from the project root (two levels above src/)
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from installer import run_installer
from logger import setup_logger
from report import generate_report
from scanner import scan_installers
from validator import validate_all
import virustotal as vt
import status


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def resolve_path(base: str, relative: str) -> str:
    return os.path.normpath(os.path.join(base, relative))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto Deploy Audit — automated, auditable software installer"
    )
    parser.add_argument(
        "--config",
        default=os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml"),
        help="Path to config.yaml (default: config/config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and validate only — do not run any installer",
    )
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    if not os.path.isfile(config_path):
        print(f"[ERROR] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = load_config(config_path)
    base_dir = os.path.dirname(config_path)
    project_root = os.path.normpath(os.path.join(base_dir, ".."))

    installers_dir = resolve_path(project_root, config.get("installers_dir", "installers"))
    logs_dir = resolve_path(project_root, config.get("logs_dir", "logs"))
    reports_dir = resolve_path(project_root, config.get("reports_dir", "reports"))

    log_cfg = config.get("logging", {})
    logger = setup_logger(
        logs_dir,
        level=log_cfg.get("level", "INFO"),
        fmt=log_cfg.get("format", "json"),
    )

    logger.info("Auto Deploy Audit started")
    logger.info(f"Config: {config_path}")

    whitelist = config.get("whitelist")
    try:
        installers = scan_installers(installers_dir, whitelist)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        sys.exit(1)

    if not installers:
        logger.warning("No installers found. Nothing to do.")
        sys.exit(0)

    logger.info(f"Detected {len(installers)} installer(s): {[os.path.basename(p) for p in installers]}")

    hashes: Dict[str, str] = config.get("hashes") or {}
    if config.get("validate_hash", False):
        logger.info("Validating file integrity (SHA-256)...")
        validation = validate_all(installers, hashes)
        invalid = [name for name, ok in validation.items() if ok is False]
        unchecked = [name for name, ok in validation.items() if ok is None]
        if unchecked:
            logger.warning(f"No hash configured for: {unchecked} — skipping validation")
        if invalid:
            logger.error(f"Hash mismatch — aborting. Files: {invalid}")
            sys.exit(1)
        logger.info("Integrity check passed.")

    if args.dry_run:
        logger.info("Dry-run mode active — skipping installation.")
        sys.exit(0)

    # VirusTotal pre-install scan
    vt_cfg = config.get("virustotal", {})
    vt_enabled = vt_cfg.get("enabled", False)
    approved: List[str] = []
    results: List[Dict] = []

    if vt_enabled:
        api_key = os.environ.get("VT_API_KEY") or vt_cfg.get("api_key", "")
        if not api_key:
            logger.error(
                "VirusTotal is enabled but no api_key found. "
                "Set the VT_API_KEY environment variable or add api_key to config.yaml."
            )
            sys.exit(1)

        upload_unknown = vt_cfg.get("upload_unknown", False)
        block_unknown = vt_cfg.get("block_unknown", False)
        malicious_threshold = int(vt_cfg.get("malicious_threshold", 1))
        suspicious_threshold = int(vt_cfg.get("suspicious_threshold", 3))

        logger.info("VirusTotal scanning enabled — checking installers before execution...")

        status.separator()
        for path in installers:
            filename = os.path.basename(path)
            now = datetime.now(timezone.utc).isoformat()
            try:
                status.scanning(filename)
                logger.info(f"VT scan: {filename}")
                scan_result = vt.scan(path, api_key, upload_unknown=upload_unknown)
                v = vt.verdict(scan_result, malicious_threshold, suspicious_threshold)

                logger.info(
                    f"VT result for {filename}: verdict={v} malicious={scan_result['malicious']} "
                    f"suspicious={scan_result['suspicious']} sha256={scan_result['sha256']}"
                )

                if v in ("malicious", "suspicious"):
                    reason = (
                        f"VirusTotal blocked: {scan_result['malicious']} engine(s) malicious, "
                        f"{scan_result['suspicious']} engine(s) suspicious. "
                        f"See: {scan_result.get('permalink') or 'N/A'}"
                    )
                    status.vt_blocked(
                        filename,
                        scan_result["malicious"],
                        scan_result["suspicious"],
                        scan_result.get("permalink") or "N/A",
                    )
                    logger.error(f"Blocked {filename}: {reason}")
                    results.append({
                        "file": filename,
                        "path": path,
                        "started_at": now,
                        "finished_at": now,
                        "status": "blocked",
                        "return_code": None,
                        "error": reason,
                        "vt_scan": scan_result,
                    })

                elif v == "unknown" and block_unknown:
                    reason = (
                        f"VirusTotal blocked: file not found in database and block_unknown is enabled. "
                        f"sha256={scan_result['sha256']}"
                    )
                    status.vt_unknown(filename, scan_result["sha256"])
                    logger.error(f"Blocked {filename}: {reason}")
                    results.append({
                        "file": filename,
                        "path": path,
                        "started_at": now,
                        "finished_at": now,
                        "status": "blocked",
                        "return_code": None,
                        "error": reason,
                        "vt_scan": scan_result,
                    })

                else:
                    if v == "unknown":
                        status.vt_unknown(filename, scan_result["sha256"])
                        logger.warning(f"{filename} not found in VT database — proceeding anyway (block_unknown=false).")
                    else:
                        status.vt_clean(
                            filename,
                            scan_result["malicious"],
                            scan_result["suspicious"],
                            scan_result["harmless"],
                        )
                        logger.info(f"{filename} cleared by VirusTotal.")
                    approved.append(path)

            except vt.VirusTotalError as exc:
                status.vt_error(filename, str(exc))
                logger.error(f"VT scan error for {filename}: {exc} — blocking as precaution.")
                results.append({
                    "file": filename,
                    "path": path,
                    "started_at": now,
                    "finished_at": now,
                    "status": "blocked",
                    "return_code": None,
                    "error": f"VirusTotal scan error: {exc}",
                    "vt_scan": None,
                })
    else:
        approved = installers

    if not approved:
        logger.warning("No installers passed the VirusTotal check. Nothing to install.")
        report_path = generate_report(results, reports_dir)
        logger.info(f"Report saved: {report_path}")
        sys.exit(1)

    # Execute approved installers
    status.separator()
    mode = config.get("execution_mode", "sequential")

    if mode == "parallel":
        max_workers = int(config.get("max_workers", 4))
        logger.info(f"Parallel mode — max_workers={max_workers}")
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(run_installer, path, logger): path for path in approved}
            for future in as_completed(futures):
                results.append(future.result())
    else:
        logger.info("Sequential mode")
        for path in approved:
            results.append(run_installer(path, logger))

    report_path = generate_report(results, reports_dir)
    logger.info(f"Report saved: {report_path}")

    total     = len(results)
    ok        = sum(1 for r in results if r.get("status") == "success")
    blocked   = sum(1 for r in results if r.get("status") == "blocked")
    failed_count = total - ok - blocked

    status.summary(total, ok, blocked, failed_count)

    if ok < total:
        logger.warning(f"{total - ok} installation(s) failed or were blocked. Review the report.")
        sys.exit(1)

    logger.info("All installations completed successfully.")


if __name__ == "__main__":
    main()
