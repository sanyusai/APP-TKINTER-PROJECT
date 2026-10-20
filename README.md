# USB Security Auditor

A desktop application (Python + **Tkinter**) that inspects the files on a USB drive or any folder using **8 static security
checks**, calculates a **0-100 risk score** for every file and produces a corporate-style **PDF audit report**.

Files are only *read*, never executed. Results are heuristic indicators for review, not proof that a file is malicious or safe.

## The five modules

| # | Module | What it does |
|---|--------|--------------|
| 1 | Dashboard | Scan statistics, recent scans, risk-distribution chart, *Start New Scan* |
| 2 | Select Device | Lists drives (USB drives highlighted) or lets you *Browse Folder* |
| 3 | File Explorer | Lists the files (search, type filter, sortable columns) and sets the scan options |
| 4 | Analysis Results | Live progress bar, risk-coloured table, quick view and a full *File Details* window |
| 5 | Reports & History | Past scans, **PDF audit report**, CSV export, re-open an old scan |

## The 8 checks and the risk score

| # | Check | Points |
|---|-------|--------|
| 1 | Extension / executable type (`.exe .bat .ps1 .vbs .js` ... and `autorun.inf`) | +10 |
| 2 | Double extension (`invoice.pdf.exe`, hidden right-to-left override, space padding) | +20 |
| 3 | File signature: magic bytes vs. extension (`MZ`, `%PDF-`, `PK`, PNG, JPEG ...) | +20 |
| 4 | Metadata: hidden executables, future or implausibly old timestamps | +5 |
| 5 | Entropy of the first 64 KB (packed / encrypted data; ignored for already-compressed types) | +10 |
| 6 | PE header: `MZ`, `PE\0\0`, sections, optional header, flags (Windows executables) | +25 |
| 7 | Size above the threshold, or an empty executable | +5 |
| 8 | SHA-256 fingerprint (recorded, adds no points) | 0 |

The total is capped at 100. Related findings are not counted twice (a fake `.exe` is penalised once, under check 6).

`0-19` Low concern  |  `20-49` Review recommended  |  `50-74` Elevated concern  |  `75-100` High concern

## Setup

You need **Python 3.9 or newer with Tkinter**.

```bash
git clone <your-repo-url>
cd usb-security-auditor
python -m pip install -r requirements.txt      # installs reportlab (PDF reports)
python main.py                                  # use python3 on macOS / Linux
```

* **Windows:** install Python from python.org (Tkinter is included). Run `python main.py`.
* **macOS:** the python.org installer includes Tkinter. With Homebrew Python install it separately:
  `brew install python-tk@3.12` (match your Python version). The first time you open a USB drive, macOS may ask for
  permission to access removable volumes: click *Allow*.
* **Linux:** `sudo apt install python3-tk`

## Try it without any malware

```bash
python make_test_files.py
```

Then: *Select Device* -> *Browse Folder* -> `test_files/sample_usb` -> set the threshold to **1 MB** -> *Analyse*.
See [`test_files/README.md`](test_files/README.md) for the expected result of every sample file.

## Project structure

```
usb-security-auditor/
├── main.py                  entry point: creates the window and starts the event loop
├── ui/                      ---- the Tkinter FRONTEND ----
│   ├── app.py               main window: sidebar, header, page switching, shared data
│   ├── theme.py             colours, fonts, ttk styles, reusable widget builders
│   ├── base.py              parent class of all pages
│   ├── dashboard.py         Module 1
│   ├── devices.py           Module 2
│   ├── files.py             Module 3
│   ├── results.py           Module 4 (scan loop with after())
│   ├── details.py           File Details window (Toplevel)
│   └── reports.py           Module 5
├── core/                    ---- the ENGINE (no Tkinter code) ----
│   ├── scanner.py           the 8 checks, scoring, file listing
│   ├── devices.py           drive detection (Windows / macOS / Linux)
│   ├── history.py           scan history (memory + JSON file)
│   └── report_pdf.py        PDF report (reportlab)
├── tests/test_scanner.py    20 unit tests for the engine and PDF
├── make_test_files.py       creates harmless demo files
└── VIVA_NOTES.md            explanation guide for the evaluation
```

Run the tests with `python -m unittest discover -s tests -v`.

## Limitations

* Static analysis only: it cannot detect every threat and is **not** an antivirus replacement.
* Only the first 64 KB of each file is used for the signature, entropy and PE checks.
* Windows reports external hard disks as fixed drives, so only USB sticks/cards are labelled *USB / Removable* there;
  use *Browse Folder* for anything else.
* Scans are limited to 5000 files; the last 10 scans are kept in `~/.usb_security_auditor/scan_history.json`.
