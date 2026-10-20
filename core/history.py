"""
history.py - keeps a record of every scan so the Dashboard and Reports pages can show it.

Records live in memory while the app runs and are also saved to a small JSON file in
the user's home folder so the history survives a restart.
"""
from __future__ import annotations

import json
import platform
from datetime import datetime
from pathlib import Path

from core import scanner

DATA_DIR = Path.home() / ".usb_security_auditor"
HISTORY_FILE = DATA_DIR / "scan_history.json"
MAX_RECORDS = 10


def new_record(root: str, results: list[dict], threshold_mb: int, recursive: bool,
               status: str, seconds: float, truncated: bool = False) -> dict:
    """Bundle one finished scan into a single dictionary."""
    now = datetime.now()
    return {
        "report_id": f"USA-{now:%Y%m%d-%H%M%S}",
        "scanned_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "root": str(root),
        "threshold_mb": threshold_mb,
        "recursive": recursive,
        "status": status,                      # "Completed" or "Stopped early"
        "seconds": round(seconds, 1),
        "truncated": truncated,                # True if the file-count limit was hit
        "host": f"{platform.system()} {platform.release()}",
        "tool_version": scanner.SCANNER_VERSION,
        "summary": scanner.summarise(results),
        "results": results,
    }


def load_history() -> list[dict]:
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_history(records: list[dict]) -> None:
    """Write via a temporary file so a crash can never leave a half-written history."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temp = HISTORY_FILE.with_suffix(".tmp")
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(records[:MAX_RECORDS], handle)
        temp.replace(HISTORY_FILE)
    except OSError:
        pass                                   # history is a convenience; never crash because of it
