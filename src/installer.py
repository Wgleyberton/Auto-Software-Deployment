import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict

import status

TIMEOUT_SECONDS = 300


def run_installer(filepath: str, logger) -> Dict:
    filename = os.path.basename(filepath)
    result: Dict = {
        "file": filename,
        "path": filepath,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "status": None,
        "return_code": None,
        "error": None,
    }

    start = time.monotonic()

    try:
        status.installing(filename)
        logger.info(f"Installing: {filename}")
        cmd = _build_command(filepath)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        elapsed = time.monotonic() - start
        result["return_code"] = proc.returncode

        if proc.returncode == 0:
            result["status"] = "success"
            status.success(filename, elapsed)
            logger.info(f"Success: {filename} ({elapsed:.1f}s)")
        else:
            result["status"] = "failed"
            result["error"] = (proc.stderr or proc.stdout).strip()
            status.failed(filename, proc.returncode, elapsed)
            logger.error(f"Failed: {filename} — exit code {proc.returncode}")

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        result["status"] = "timeout"
        result["error"] = f"Timed out after {TIMEOUT_SECONDS}s"
        status.timeout_expired(filename, TIMEOUT_SECONDS)
        logger.error(f"Timeout: {filename}")

    except Exception as exc:
        elapsed = time.monotonic() - start
        result["status"] = "error"
        result["error"] = str(exc)
        status.install_error(filename, str(exc))
        logger.exception(f"Unexpected error installing {filename}")

    finally:
        result["finished_at"] = datetime.now(timezone.utc).isoformat()

    return result


def _build_command(filepath: str) -> list:
    ext = os.path.splitext(filepath)[1].lower()
    system = platform.system()

    if system == "Windows":
        if ext == ".exe":
            return [filepath, "/S"]
        if ext == ".msi":
            return ["msiexec", "/i", filepath, "/quiet", "/norestart"]
    else:
        if ext == ".sh":
            return ["bash", filepath]
        if ext == ".deb":
            return ["sudo", "dpkg", "-i", filepath]
        if ext == ".rpm":
            return ["sudo", "rpm", "-i", filepath]
        if ext == ".pkg":
            return ["sudo", "installer", "-pkg", filepath, "-target", "/"]

    return [filepath]
