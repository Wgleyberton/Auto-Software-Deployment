import os
import sys
from datetime import datetime

# ── ANSI colour codes ─────────────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GRAY   = "\033[90m"
_WHITE  = "\033[97m"


def _ansi_supported() -> bool:
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Enable virtual terminal processing on Windows 10+
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    return True


_USE_ANSI = _ansi_supported()


def _c(text: str, *codes: str) -> str:
    return ("".join(codes) + text + _RESET) if _USE_ANSI else text


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _line(label: str, label_color: str, filename: str, detail: str = "") -> None:
    tag = _c(f" {label:<11}", label_color, _BOLD)
    name = _c(filename, _WHITE)
    suffix = ("  " + _c(detail, _GRAY)) if detail else ""
    print(f"[{tag}]  {_ts()}  {name}{suffix}", flush=True)


# ── Public API ────────────────────────────────────────────────────────────────

def scanning(filename: str) -> None:
    _line("SCANNING", _CYAN, filename)


def vt_clean(filename: str, malicious: int, suspicious: int, harmless: int) -> None:
    detail = f"malicious={malicious}  suspicious={suspicious}  harmless={harmless}"
    _line("CLEAN", _GREEN, filename, detail)


def vt_blocked(filename: str, malicious: int, suspicious: int, permalink: str) -> None:
    detail = f"{malicious} malicious  {suspicious} suspicious  >>  {permalink}"
    _line("BLOCKED", _RED, filename, detail)


def vt_unknown(filename: str, sha256: str) -> None:
    detail = f"not in VT database  sha256={sha256[:16]}..."
    _line("UNKNOWN", _YELLOW, filename, detail)


def vt_error(filename: str, message: str) -> None:
    _line("VT ERROR", _RED, filename, message)


def installing(filename: str) -> None:
    _line("INSTALLING", _CYAN, filename, "executing...")


def success(filename: str, elapsed: float) -> None:
    _line("SUCCESS", _GREEN, filename, f"{elapsed:.1f}s")


def failed(filename: str, return_code: int, elapsed: float) -> None:
    detail = f"exit code={return_code}  {elapsed:.1f}s"
    _line("FAILED", _RED, filename, detail)


def timeout_expired(filename: str, seconds: int) -> None:
    _line("TIMEOUT", _RED, filename, f"exceeded {seconds}s limit")


def install_error(filename: str, message: str) -> None:
    _line("ERROR", _RED, filename, message)


def separator() -> None:
    line = _c("-" * 72, _GRAY)
    print(line, flush=True)


def summary(total: int, ok: int, blocked: int, failed: int) -> None:
    print(flush=True)
    separator()
    label = _c("SUMMARY", _WHITE, _BOLD)
    print(f"  {label}", flush=True)
    print(f"  Total     : {_c(str(total),  _WHITE)}", flush=True)
    print(f"  Success   : {_c(str(ok),     _GREEN  if ok      else _GRAY)}", flush=True)
    print(f"  Blocked   : {_c(str(blocked),_RED    if blocked else _GRAY)}", flush=True)
    print(f"  Failed    : {_c(str(failed), _RED    if failed  else _GRAY)}", flush=True)
    separator()
    print(flush=True)
