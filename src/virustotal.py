import hashlib
import time
from typing import Dict, Optional

import requests

VT_API_BASE = "https://www.virustotal.com/api/v3"
_POLL_INTERVAL = 15
_MAX_POLLS = 24  # 24 × 15s = 6 minutes max wait


class VirusTotalError(Exception):
    pass


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key}


def _sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _query_hash(sha256: str, api_key: str) -> Optional[dict]:
    """Returns the VT file report or None if the hash is unknown."""
    try:
        resp = requests.get(
            f"{VT_API_BASE}/files/{sha256}",
            headers=_headers(api_key),
            timeout=30,
        )
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error querying hash: {exc}") from exc

    if resp.status_code == 404:
        return None
    if resp.status_code == 401:
        raise VirusTotalError("Invalid or unauthorized VirusTotal API key.")
    if resp.status_code == 429:
        raise VirusTotalError("VirusTotal API rate limit exceeded. Try again later.")
    resp.raise_for_status()
    return resp.json()


def _upload_file(filepath: str, api_key: str) -> str:
    """Uploads the file to VT and returns the analysis ID."""
    try:
        with open(filepath, "rb") as fh:
            resp = requests.post(
                f"{VT_API_BASE}/files",
                headers=_headers(api_key),
                files={"file": (filepath, fh)},
                timeout=120,
            )
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error uploading file: {exc}") from exc

    if resp.status_code == 429:
        raise VirusTotalError("VirusTotal API rate limit exceeded during upload.")
    resp.raise_for_status()
    return resp.json()["data"]["id"]


def _poll_analysis(analysis_id: str, api_key: str) -> dict:
    """Polls VT until analysis completes and returns the stats dict."""
    url = f"{VT_API_BASE}/analyses/{analysis_id}"
    for _ in range(_MAX_POLLS):
        try:
            resp = requests.get(url, headers=_headers(api_key), timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise VirusTotalError(f"Network error polling analysis: {exc}") from exc

        data = resp.json()["data"]
        if data["attributes"]["status"] == "completed":
            return data["attributes"].get("stats", {})
        time.sleep(_POLL_INTERVAL)

    raise VirusTotalError("Timed out waiting for VirusTotal analysis to complete.")


def _build_result(sha256: str, stats: dict, found_in_db: bool, skipped: bool = False) -> Dict:
    return {
        "sha256": sha256,
        "found_in_db": found_in_db,
        "skipped": skipped,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        # permalink is always available once the hash is known by VT
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def scan(filepath: str, api_key: str, upload_unknown: bool = False) -> Dict:
    """
    Scans a file against VirusTotal.

    Flow:
      1. Compute SHA-256 and query VT by hash (free, no quota consumed).
      2. If hash is unknown and upload_unknown=True, upload and poll for results.
      3. If hash is unknown and upload_unknown=False, return skipped=True.

    Returns a dict with keys:
      sha256, found_in_db, skipped, malicious, suspicious,
      harmless, undetected, permalink
    """
    sha256 = _sha256(filepath)
    report = _query_hash(sha256, api_key)

    if report is not None:
        stats = report["data"]["attributes"].get("last_analysis_stats", {})
        return _build_result(sha256, stats, found_in_db=True)

    if not upload_unknown:
        return {
            "sha256": sha256,
            "found_in_db": False,
            "skipped": True,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    analysis_id = _upload_file(filepath, api_key)
    stats = _poll_analysis(analysis_id, api_key)
    return _build_result(sha256, stats, found_in_db=False)


def verdict(scan_result: Dict, malicious_threshold: int, suspicious_threshold: int) -> str:
    """
    Returns 'clean', 'suspicious', 'malicious', or 'unknown'.
    'unknown' means the file was not in the VT database and upload was disabled.
    """
    if scan_result.get("skipped"):
        return "unknown"
    if scan_result["malicious"] >= malicious_threshold:
        return "malicious"
    if scan_result["suspicious"] >= suspicious_threshold:
        return "suspicious"
    return "clean"
