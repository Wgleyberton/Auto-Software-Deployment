import hashlib
import os
from typing import Dict, List, Optional


def compute_sha256(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def validate_file(filepath: str, expected_hash: str) -> bool:
    return compute_sha256(filepath).lower() == expected_hash.lower()


def validate_all(
    installers: List[str],
    hashes: Dict[str, str],
) -> Dict[str, Optional[bool]]:
    """
    Returns a dict mapping filename → True (ok) | False (mismatch) | None (no hash configured).
    """
    results: Dict[str, Optional[bool]] = {}
    for path in installers:
        name = os.path.basename(path)
        if name in hashes:
            results[name] = validate_file(path, hashes[name])
        else:
            results[name] = None
    return results
