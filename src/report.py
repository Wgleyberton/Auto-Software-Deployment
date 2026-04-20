import json
import os
from datetime import datetime, timezone
from typing import Dict, List


def generate_report(results: List[Dict], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    total = len(results)
    success = sum(1 for r in results if r.get("status") == "success")
    blocked = sum(1 for r in results if r.get("status") == "blocked")
    failed = total - success - blocked

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": total,
            "success": success,
            "blocked_by_virustotal": blocked,
            "failed": failed,
        },
        "results": results,
    }

    report_path = os.path.join(output_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    return report_path
