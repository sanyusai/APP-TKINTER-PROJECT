"""
devices.py - find the storage devices (drives) connected to the computer.

Detecting a *USB* drive is different on every operating system, so there is one
small function per OS. If detection does not work on a machine, the GUI always has
a "Browse Folder" button as a fallback.
"""
from __future__ import annotations

import os
import platform
import plistlib
import shutil
import subprocess
from pathlib import Path


def _usage(path: str) -> tuple[int | None, int | None]:
    """Return (total bytes, free bytes) or (None, None) if the drive can't be read."""
    try:
        usage = shutil.disk_usage(path)
        return usage.total, usage.free
    except OSError:
        return None, None


def _device(name: str, path: str, kind: str, removable: bool) -> dict:
    total, free = _usage(path)
    return {"name": name, "path": path, "kind": kind, "removable": removable, "total": total, "free": free}


# ---------------------------------------------------------------- Windows
def _windows_drives() -> list[dict]:
    import ctypes
    import string

    kernel32 = ctypes.windll.kernel32                       # type: ignore[attr-defined]
    kernel32.SetErrorMode(0x0001)                           # don't show "no disk in drive" pop-ups
    names = {2: "USB / Removable", 3: "Fixed disk", 4: "Network drive", 6: "RAM disk"}
    devices = []
    mask = kernel32.GetLogicalDrives()                      # bit 0 = A:, bit 1 = B:, ...
    for index, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << index):
            continue
        root = f"{letter}:\\"
        drive_type = kernel32.GetDriveTypeW(root)           # 2 = removable, 3 = fixed, 5 = CD-ROM ...
        if drive_type not in names:
            continue
        label = ctypes.create_unicode_buffer(261)
        kernel32.GetVolumeInformationW(root, label, 261, None, None, None, None, 0)
        volume = label.value or "Local Disk"
        device = _device(f"{volume} ({letter}:)", root, names[drive_type], drive_type == 2)
        if device["total"] is None:                         # e.g. an empty card-reader slot
            device["kind"] += " (not ready)"
        devices.append(device)
    return devices


# ------------------------------------------------------------------ macOS
def _mac_volumes() -> list[dict]:
    devices = []
    volumes = Path("/Volumes")
    if not volumes.exists():
        return devices
    for entry in sorted(volumes.iterdir(), key=lambda p: p.name.lower()):
        if entry.is_symlink() or not entry.is_dir():        # "Macintosh HD" is a symlink to /
            continue
        kind, removable = "Mounted volume", False
        try:
            output = subprocess.run(["diskutil", "info", "-plist", str(entry)],
                                    capture_output=True, timeout=5, check=True).stdout
            info = plistlib.loads(output)
            if info.get("BusProtocol") == "Disk Image":      # a mounted .dmg is not a physical drive
                devices.append(_device(entry.name, str(entry), "Disk image", False))
                continue
            external = (info.get("BusProtocol") == "USB" or info.get("Removable") or info.get("Ejectable")
                        or info.get("RemovableMediaOrExternalDevice") or info.get("Internal") is False)
            if external:
                kind, removable = "USB / External", True
            else:
                kind = "Internal disk"
        except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException, ValueError):
            pass
        devices.append(_device(entry.name, str(entry), kind, removable))
    return devices


# ------------------------------------------------------------------ Linux
def _linux_mounts() -> list[dict]:
    user = os.environ.get("USER", "")
    candidates = []
    for base in (f"/media/{user}", f"/run/media/{user}", "/media", "/mnt"):
        basepath = Path(base)
        if basepath.is_dir():
            candidates += [p for p in sorted(basepath.iterdir()) if p.is_dir()]
    return [_device(p.name, str(p), "Mounted volume", True) for p in candidates if os.path.ismount(p)]


# ----------------------------------------------------------------- public
def list_devices() -> list[dict]:
    """Return a list of devices, removable ones first. Never raises."""
    system = platform.system()
    try:
        if system == "Windows":
            devices = _windows_drives()
        elif system == "Darwin":
            devices = _mac_volumes()
        else:
            devices = _linux_mounts()
    except Exception:                                        # detection must never crash the GUI
        devices = []
    return sorted(devices, key=lambda d: (not d["removable"], d["name"].lower()))
