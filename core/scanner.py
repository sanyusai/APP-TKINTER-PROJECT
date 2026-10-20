"""
scanner.py - the static-analysis engine of the USB Security Auditor.

IMPORTANT: there is NO Tkinter code in this file. The GUI only calls the
functions below and displays what they return. Files are only READ, never run.

The engine performs 8 checks on every file:
    1. Extension / executable type      5. Lightweight entropy
    2. Double extension                 6. PE header inspection
    3. File signature (magic bytes)     7. File size / empty file
    4. Metadata (filesystem properties) 8. SHA-256 fingerprint
Each check returns points; the points are added up (max 100) to give a risk score.

All results are heuristic indicators for human review. They are NOT proof that a
file is malicious or safe.
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCANNER_VERSION = "1.0"

# --------------------------------------------------------------------------
# Configuration (kept as plain constants so they are easy to explain)
# --------------------------------------------------------------------------
SAMPLE_BYTES = 64 * 1024          # how many bytes we read for signature/entropy
MAX_FILES = 5000                  # safety limit for one scan
ENTROPY_HIGH = 7.2                # bits per byte (max possible is 8.0)
FLAG_THRESHOLD = 20               # score >= 20 counts as "flagged for review"

# Points added to the risk score for each finding
POINTS = {
    "extension": 10,
    "double_extension": 20,
    "signature": 20,
    "pe": 25,
    "entropy": 10,
    "metadata": 5,
    "size": 5,
}

# Extensions that can run code, with a short description used as evidence.
EXECUTABLE_EXTS = {
    ".exe": "Windows program", ".dll": "Windows library", ".scr": "screensaver program",
    ".com": "DOS/Windows program", ".msi": "installer package", ".bat": "batch script",
    ".cmd": "batch script", ".ps1": "PowerShell script", ".vbs": "VBScript",
    ".js": "JavaScript (Windows Script Host)", ".wsf": "Windows script file",
    ".hta": "HTML application", ".jar": "Java archive", ".lnk": "shortcut file",
    ".pif": "program shortcut", ".reg": "registry script", ".sh": "shell script",
    ".command": "macOS shell script",
}
# Extensions that are expected to be real Windows PE files.
PE_EXTS = {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl"}

# "Decoy" extensions: harmless-looking types used to hide a real executable
# extension, e.g. invoice.pdf.exe
DECOY_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".csv", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip",
}

# Magic bytes: (first bytes of file, description, extensions that are normal for it)
_ZIP_EXTS = {
    ".zip", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".jar", ".apk",
    ".odt", ".ods", ".odp", ".epub", ".xpi", ".whl", ".war", ".kmz", ".vsix", ".nupkg",
}
SIGNATURES = [
    (b"MZ", "Windows executable (PE)", {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".com"}),
    (b"%PDF-", "PDF document", {".pdf"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg", ".jpe"}),
    (b"GIF87a", "GIF image", {".gif"}),
    (b"GIF89a", "GIF image", {".gif"}),
    (b"PK\x03\x04", "ZIP-based file (ZIP/Office/JAR)", _ZIP_EXTS),
    (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (b"\x1f\x8b", "GZIP archive", {".gz", ".tgz"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy Office (OLE) file", {".doc", ".xls", ".ppt", ".msi", ".msg"}),
    (b"\x7fELF", "Linux executable (ELF)", {"", ".elf", ".so", ".bin", ".out"}),
    (b"\xcf\xfa\xed\xfe", "macOS executable (Mach-O)", {"", ".dylib", ".bin", ".o"}),
    (b"\xca\xfe\xba\xbe", "macOS universal binary / Java class", {"", ".dylib", ".bin", ".class"}),
]
# Detected types that are executable content (used for wording and entropy logic)
EXECUTABLE_LABELS = {"Windows executable (PE)", "Linux executable (ELF)", "macOS executable (Mach-O)"}

# Extensions that MUST carry a known header; if it is missing, that is a mismatch.
CLAIMED_FORMATS = {
    ".pdf": "PDF document", ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image",
    ".gif": "GIF image", ".exe": "Windows executable (PE)", ".dll": "Windows executable (PE)",
    ".zip": "ZIP archive", ".docx": "Office (ZIP-based) document", ".xlsx": "Office (ZIP-based) document",
    ".pptx": "Office (ZIP-based) document", ".rar": "RAR archive", ".7z": "7-Zip archive",
}

# File types that are already compressed, so high entropy is NORMAL for them.
NATURALLY_HIGH_ENTROPY = {
    ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".jpg", ".jpeg", ".png", ".gif",
    ".webp", ".heic", ".mp3", ".mp4", ".mov", ".mkv", ".avi", ".flac", ".aac", ".gz",
    ".rar", ".7z", ".pdf", ".epub", ".odt", ".ods", ".odp",
}

# Folders that operating systems create on drives; skipped to avoid noise/permission errors.
SKIP_DIRS = {"$recycle.bin", "system volume information", ".spotlight-v100", ".fseventsd",
             ".trashes", ".temporaryitems", ".documentrevisions-v100"}

LEVELS = [  # (minimum score, label)
    (0, "Low concern"),
    (20, "Review recommended"),
    (50, "Elevated concern"),
    (75, "High concern"),
]
LEVEL_ERROR = "Could not analyse"
ALL_LEVELS = [label for _, label in LEVELS] + [LEVEL_ERROR]

RECOMMENDATIONS = {
    "Low concern": "No action needed beyond normal hygiene. Few or no indicators were found, "
                   "but this does not certify the file as safe.",
    "Review recommended": "Confirm where the file came from before opening it. If its origin is unknown, "
                          "scan it with an up-to-date antivirus first.",
    "Elevated concern": "Do not open this file on a production machine. Scan it with antivirus and "
                        "look up its SHA-256 on a reputation service (for example VirusTotal).",
    "High concern": "Isolate the file now. Do not open or run it. Analyse it only inside a sandbox or "
                    "virtual machine and report it to the security team.",
    LEVEL_ERROR: "The file could not be read (permissions, in use, or disk error). "
                 "Retry the scan or inspect the file manually.",
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def human_size(num_bytes: int | float | None) -> str:
    """Turn 2048 into '2.0 KB'."""
    if num_bytes is None:
        return "-"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_time(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "unknown"


def level_for_score(score: int) -> str:
    """Convert a 0-100 score into an assessment label."""
    label = LEVELS[0][1]
    for minimum, name in LEVELS:
        if score >= minimum:
            label = name
    return label


def _check(number: int, name: str, status: str, points: int, evidence: str) -> dict:
    """Every check returns a dict of this shape. status: PASS / FLAG / INFO / N/A / ERROR."""
    return {"number": number, "name": name, "status": status, "points": points, "evidence": evidence}


# --------------------------------------------------------------------------
# Check 8 - SHA-256 fingerprint
# --------------------------------------------------------------------------
def calculate_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash the file in 1 MB chunks so even huge files never fill the memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:           # "rb" = read raw bytes
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Check 1 - extension / executable type
# --------------------------------------------------------------------------
def check_extension(name: str, ext: str) -> dict:
    title = "Extension / executable type"
    if name.lower() == "autorun.inf":
        return _check(1, title, "FLAG", POINTS["extension"],
                      "autorun.inf can make Windows launch a program automatically from a removable drive.")
    if ext in EXECUTABLE_EXTS:
        return _check(1, title, "FLAG", POINTS["extension"],
                      f"'{ext}' is a {EXECUTABLE_EXTS[ext]}. It can run code, though it may be legitimate.")
    return _check(1, title, "PASS", 0, f"'{ext or 'none'}' is not an executable or script type.")


# --------------------------------------------------------------------------
# Check 2 - double extension
# --------------------------------------------------------------------------
def check_double_extension(name: str) -> dict:
    title = "Double extension"
    suffixes = [s.lower() for s in Path(name).suffixes]
    reasons = []
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTS and suffixes[-2] in DECOY_EXTS:
        reasons.append(f"'{suffixes[-2]}' is followed by the executable extension '{suffixes[-1]}' "
                       f"(looks like a document but runs as a program)")
    if "‮" in name:                         # right-to-left override character
        reasons.append("contains a hidden right-to-left override character that reverses the displayed name")
    stem_part = name.rsplit(".", 1)[0] if "." in name else name
    if len(stem_part) - len(stem_part.rstrip()) >= 5:
        reasons.append("name is padded with spaces so the real extension is pushed out of view")
    if reasons:
        return _check(2, title, "FLAG", POINTS["double_extension"], "; ".join(reasons) + ".")
    return _check(2, title, "PASS", 0, "No deceptive extension pattern in the filename.")


# --------------------------------------------------------------------------
# Check 3 - file signature (magic bytes)
# --------------------------------------------------------------------------
def check_signature(ext: str, head: bytes) -> tuple[dict, str | None]:
    """Compare the first bytes of the file with its extension. Returns (check, detected type)."""
    title = "File signature (magic bytes)"
    if not head:
        return _check(3, title, "INFO", 0, "File is empty, so there is no header to compare."), None

    detected = None
    for magic, label, allowed in SIGNATURES:
        if head.startswith(magic):
            detected = (label, allowed)
            break

    first_bytes = head[:8].hex(" ").upper()
    if detected:
        label, allowed = detected
        if ext in allowed:
            return _check(3, title, "PASS", 0, f"Header ({first_bytes}) matches the extension: {label}."), label
        expected = ", ".join(sorted(e for e in allowed if e)) or "no extension"
        extra = " Executable content is hidden behind a non-executable name." if label in EXECUTABLE_LABELS else ""
        return _check(3, title, "FLAG", POINTS["signature"],
                      f"Header ({first_bytes}) says {label}, but the extension is '{ext or 'none'}' "
                      f"(expected: {expected}).{extra}"), label

    # No known header was found. Is that a problem for this extension?
    if ext in CLAIMED_FORMATS:
        if ext == ".pdf" and b"%PDF-" in head[:1024]:     # PDF readers accept a short prefix
            return _check(3, title, "PASS", 0, "PDF header found near the start of the file."), "PDF document"
        return _check(3, title, "FLAG", POINTS["signature"],
                      f"Extension '{ext}' claims a {CLAIMED_FORMATS[ext]}, but the file starts with "
                      f"{first_bytes}, which is not that format."), None
    return _check(3, title, "INFO", 0, f"No known binary signature (first bytes: {first_bytes}); "
                                       "probably plain text or an unlisted format."), None


# --------------------------------------------------------------------------
# Check 4 - metadata (filesystem properties)
# --------------------------------------------------------------------------
def check_metadata(st: os.stat_result, name: str, ext: str) -> dict:
    title = "Metadata / file properties"
    problems = []
    attributes = getattr(st, "st_file_attributes", 0)       # only exists on Windows
    hidden = name.startswith(".") or bool(attributes & 0x2)  # 0x2 = FILE_ATTRIBUTE_HIDDEN
    if hidden and ext in EXECUTABLE_EXTS:
        problems.append("hidden executable/script")
    if st.st_mtime > time.time() + 86400:
        problems.append("modified date is in the future")
    if st.st_mtime < 631152000:                              # before 1990-01-01
        problems.append("modified date is implausibly old (possibly stripped or forged)")
    created = getattr(st, "st_birthtime", None) or st.st_ctime
    summary = f"Modified {format_time(st.st_mtime)}, created {format_time(created)}, {human_size(st.st_size)}."
    if problems:
        return _check(4, title, "FLAG", POINTS["metadata"], "; ".join(problems).capitalize() + ". " + summary)
    return _check(4, title, "PASS", 0, summary + " No unusual properties.")


# --------------------------------------------------------------------------
# Check 5 - lightweight entropy
# --------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: 0 = all identical bytes, 8 = perfectly random."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def check_entropy(sample: bytes, ext: str, detected: str | None) -> tuple[dict, float | None]:
    title = "Entropy (packed/encrypted data)"
    if len(sample) < 256:
        return _check(5, title, "N/A", 0, "File is too small for a meaningful entropy estimate."), None
    value = shannon_entropy(sample)
    text = f"{value:.2f} of 8.00 bits per byte (first {human_size(len(sample))} sampled)."
    if value >= ENTROPY_HIGH:
        if ext in NATURALLY_HIGH_ENTROPY and detected not in EXECUTABLE_LABELS:
            return _check(5, title, "INFO", 0, text + " High, but normal for an already-compressed file type."), value
        return _check(5, title, "FLAG", POINTS["entropy"],
                      text + " Very random data can mean packed, encrypted or compressed content."), value
    return _check(5, title, "PASS", 0, text + " Within the normal range."), value


# --------------------------------------------------------------------------
# Check 6 - PE header inspection
# --------------------------------------------------------------------------
_MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM"}


def check_pe(path: Path, size: int, head: bytes, ext: str) -> dict:
    """Validate the structure of a Windows executable WITHOUT running it."""
    title = "PE header inspection"
    if not (head[:2] == b"MZ" or ext in PE_EXTS):
        return _check(6, title, "N/A", 0, "Not a Windows executable, so this check does not apply.")

    problems = []
    info = ""
    if head[:2] != b"MZ":
        problems.append("missing the DOS 'MZ' header every Windows executable starts with")
    elif size < 64:
        problems.append("file is shorter than the 64-byte DOS header")
    else:
        pe_offset = struct.unpack_from("<I", head, 0x3C)[0]          # e_lfanew: where the PE header starts
        if pe_offset < 0x40 or pe_offset > size - 24:
            problems.append(f"PE header offset 0x{pe_offset:X} points outside the file")
        else:
            with open(path, "rb") as handle:
                handle.seek(pe_offset)
                pe = handle.read(28)
            if pe[:4] != b"PE\x00\x00":
                problems.append(f"'PE\\0\\0' signature not found at offset 0x{pe_offset:X}")
            elif len(pe) < 26:
                problems.append("PE header is truncated")
            else:
                machine, sections, stamp, _sym, _nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", pe, 4)
                opt_magic = struct.unpack_from("<H", pe, 24)[0]
                if sections == 0 or sections > 96:
                    problems.append(f"unusual section count ({sections})")
                if opt_size < 96:
                    problems.append(f"optional header too small ({opt_size} bytes)")
                if opt_magic not in (0x10B, 0x20B):
                    problems.append(f"invalid optional-header magic 0x{opt_magic:X}")
                if not chars & 0x0002:
                    problems.append("not marked as an executable image")
                if stamp > time.time() + 86400:
                    problems.append("compile timestamp is in the future")
                is_dll = bool(chars & 0x2000)
                if ext == ".dll" and not is_dll:
                    problems.append("extension is .dll but the header is not a DLL")
                if ext in (".exe", ".scr") and is_dll:
                    problems.append(f"extension is {ext} but the header says DLL")
                built = (datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%d") if stamp else "not set")
                info = (f"{_MACHINES.get(machine, hex(machine))} {'DLL' if is_dll else 'EXE'}, "
                        f"{sections} section(s), compile time {built}")
    if problems:
        return _check(6, title, "FLAG", POINTS["pe"], "Malformed or inconsistent PE structure: " + "; ".join(problems) + ".")
    return _check(6, title, "PASS", 0, f"Valid PE structure: {info}.")


# --------------------------------------------------------------------------
# Check 7 - size / empty file
# --------------------------------------------------------------------------
def check_size(size: int, ext: str, threshold_mb: int) -> dict:
    title = "File size / empty file"
    limit = threshold_mb * 1024 * 1024
    if size == 0:
        if ext in EXECUTABLE_EXTS:
            return _check(7, title, "FLAG", POINTS["size"], "Empty executable/script file (placeholder or failed copy).")
        return _check(7, title, "INFO", 0, "File is empty (0 bytes).")
    if size > limit:
        return _check(7, title, "FLAG", POINTS["size"],
                      f"{human_size(size)} is larger than the {threshold_mb} MB review threshold.")
    return _check(7, title, "PASS", 0, f"{human_size(size)} is within the {threshold_mb} MB threshold.")


# --------------------------------------------------------------------------
# The main function: run all 8 checks on one file
# --------------------------------------------------------------------------
def analyze_file(path: Path | str, root: Path | str | None = None, threshold_mb: int = 100) -> dict:
    """Analyse one file and return a dictionary (easy to show in a table, CSV or PDF)."""
    path = Path(path)
    name = path.name
    ext = path.suffix.lower()
    try:
        relative = str(path.relative_to(root)) if root else name
    except ValueError:
        relative = name

    result = {
        "path": str(path), "name": name, "relative": relative, "ext": ext, "size": 0,
        "modified": "", "sha256": "", "detected_type": "", "entropy": None,
        "score": 0, "level": LEVEL_ERROR, "checks": [], "recommendation": "", "error": None,
    }
    try:
        st = path.stat()
        result["size"] = st.st_size
        result["modified"] = format_time(st.st_mtime)
        with open(path, "rb") as handle:
            head = handle.read(SAMPLE_BYTES)          # one small read feeds checks 3, 5 and 6

        c1 = check_extension(name, ext)
        c2 = check_double_extension(name)
        c3, detected = check_signature(ext, head)
        c4 = check_metadata(st, name, ext)
        c5, entropy = check_entropy(head, ext, detected)
        c6 = check_pe(path, st.st_size, head, ext)
        c7 = check_size(st.st_size, ext, threshold_mb)
        digest = calculate_sha256(path)
        c8 = _check(8, "SHA-256 fingerprint", "INFO", 0, digest)

        # Avoid double counting: a fake .exe is ONE problem, not two.
        if c6["points"] and c3["points"] and (ext in PE_EXTS or head[:2] == b"MZ"):
            c3["points"] = 0
            c3["evidence"] += " (not scored again: already counted under the PE header check)"

        checks = [c1, c2, c3, c4, c5, c6, c7, c8]
        score = min(100, sum(c["points"] for c in checks))
        result.update({
            "sha256": digest, "entropy": entropy, "checks": checks, "score": score,
            "level": level_for_score(score),
            "detected_type": detected or EXECUTABLE_EXTS.get(ext) or (f"{ext[1:].upper()} file" if ext else "No extension"),
        })
        result["recommendation"] = RECOMMENDATIONS[result["level"]]
    except (OSError, PermissionError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["recommendation"] = RECOMMENDATIONS[LEVEL_ERROR]
        result["checks"] = [_check(0, "File access", "ERROR", 0, result["error"])]
    return result


# --------------------------------------------------------------------------
# Listing files and summarising results
# --------------------------------------------------------------------------
def list_files(folder: Path | str, recursive: bool = True, limit: int = MAX_FILES) -> tuple[list[Path], bool]:
    """Return (files, truncated). Symbolic links are skipped so we never loop forever."""
    folder = Path(folder)
    files: list[Path] = []
    truncated = False
    if not recursive:
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name.lower())
        except OSError:
            return [], False
        for entry in entries:
            if entry.is_file(follow_symlinks=False):
                files.append(Path(entry.path))
                if len(files) >= limit:
                    return files, True
        return files, False

    for current, dirs, names in os.walk(folder, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d.lower() not in SKIP_DIRS)
        for filename in sorted(names, key=str.lower):
            full = Path(current) / filename
            if full.is_symlink():
                continue
            files.append(full)
            if len(files) >= limit:
                return files, True
    return files, truncated


def summarise(results: list[dict]) -> dict:
    """Totals used by the dashboard cards and by the PDF report."""
    by_level = {label: 0 for label in ALL_LEVELS}
    for r in results:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1
    scores = [r["score"] for r in results if not r["error"]]
    top = max(scores) if scores else 0
    return {
        "total": len(results),
        "flagged": sum(1 for r in results if not r["error"] and r["score"] >= FLAG_THRESHOLD),
        "clean": sum(1 for r in results if not r["error"] and r["score"] < FLAG_THRESHOLD),
        "errors": sum(1 for r in results if r["error"]),
        "by_level": by_level,
        "max_score": top,
        "average_score": round(sum(scores) / len(scores), 1) if scores else 0,
        "overall_level": level_for_score(top),
    }
