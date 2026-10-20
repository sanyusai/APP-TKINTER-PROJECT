# Test files

Run `python make_test_files.py` from the project folder. It creates **harmless** sample files in
`test_files/sample_usb/` (the folder is git-ignored, so nothing risky is ever committed).

| File | What it demonstrates | Expected result (1 MB threshold) |
|------|----------------------|----------------------------------|
| `notes.txt`, `project.pdf`, `photo.jpg`, `docs/readme.txt` | Normal files | 0 - Low concern |
| `sample.exe.txt` | Misleading name, but the real extension is `.txt` | 0 - Low concern |
| `script.bat`, `autorun.inf`, `empty_script.ps1` | Script / autorun types, empty script | 10-15 - Low concern |
| `random_payload.bin` | Very high entropy (random bytes) | 10 - Low concern |
| `large_backup.dat` | Larger than the threshold | 5 - Low concern |
| `disguised.png` | Executable header hidden behind a `.png` name | 20 - Review recommended |
| `invoice.pdf.exe` | Double extension (valid PE structure, no code) | 30 - Review recommended |
| `broken_installer.exe` | Text pretending to be a program (bad PE) | 35 - Review recommended |
| `update_installer.pdf.exe` | Fake exe + double extension + random data | 65 - Elevated concern |
| `.invoice_2026.pdf.exe` | Many indicators at once | 75 - High concern |

None of these files contains program code. Some antivirus programs dislike the `.exe` names anyway; if one is quarantined,
add the `test_files` folder to the exclusions or just re-run the script.
