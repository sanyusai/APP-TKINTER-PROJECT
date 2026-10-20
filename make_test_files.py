"""
make_test_files.py - creates a folder of HARMLESS sample files for the demo.

Nothing created here can harm a computer: the "executables" are only header bytes
with no program code, and the scripts only print text. Some antivirus programs may
still dislike the fake .exe files; if one is quarantined, just re-run this script.

Usage:   python make_test_files.py
Then in the app: Select Device -> Browse Folder -> test_files/sample_usb
Tip:     set "Large-file threshold" to 1 MB in the File Explorer to trigger the size check.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

TARGET = Path(__file__).parent / "test_files" / "sample_usb"


def fake_pe_header() -> bytes:
    """A structurally valid PE header (MZ + PE + 1 section) with NO executable code."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)                       # PE header starts at offset 0x40
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 1700000000, 0, 0, 0xF0, 0x0022)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)                    # PE32+ magic
    section = b".text\x00\x00\x00" + bytes(32)
    return bytes(dos) + coff + bytes(optional) + section + bytes(512)


def write(name: str, data: bytes | str) -> None:
    path = TARGET / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def main() -> None:
    write("notes.txt", "Meeting notes: nothing suspicious here.\n" * 20)
    write("project.pdf", "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n")
    write("photo.jpg", b"\xff\xd8\xff\xe0" + bytes(range(256)) * 8)
    write("sample.exe.txt", "This is a plain text file with a misleading name. It is not an executable.\n")
    write("docs/readme.txt", "A file inside a sub-folder (shows the recursive scan).\n")

    write("script.bat", "@echo off\necho Hello from a harmless demo script\n")
    write("autorun.inf", "[autorun]\nopen=setup.exe\n")
    write("empty_script.ps1", b"")

    write("disguised.png", fake_pe_header())                      # executable header hidden as PNG
    write("broken_installer.exe", "This is plain text pretending to be a program.\n" * 30)
    write("invoice.pdf.exe", fake_pe_header())                    # double extension, valid PE structure
    write("random_payload.bin", os.urandom(200 * 1024))           # very high entropy
    write("large_backup.dat", bytes(1_500_000))                   # > 1 MB (use a 1 MB threshold)
    write("update_installer.pdf.exe", os.urandom(100 * 1024))     # fake exe + double extension + random data
    write(".invoice_2026.pdf.exe", os.urandom(1_300_000))         # many indicators at once

    print(f"Created {sum(1 for p in TARGET.rglob('*') if p.is_file())} sample files in:\n  {TARGET}")


if __name__ == "__main__":
    main()
