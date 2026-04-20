import os
from typing import List, Optional

SUPPORTED_EXTENSIONS = {".exe", ".msi", ".sh", ".pkg", ".deb", ".rpm"}


def scan_installers(
    directory: str,
    whitelist: Optional[List[str]] = None,
) -> List[str]:
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Installers directory not found: {directory}")

    found: List[str] = []
    for filename in sorted(os.listdir(directory)):
        ext = os.path.splitext(filename)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            continue
        if whitelist is not None and filename not in whitelist:
            continue
        found.append(os.path.join(directory, filename))

    return found
