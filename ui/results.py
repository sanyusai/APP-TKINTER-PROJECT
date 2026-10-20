"""
results.py - MODULE 4: Security Analysis and Results.

Tkinter concepts shown here: after() for a non-blocking scan loop, determinate Progressbar,
metric cards (StringVar), Treeview with colour tags + sortable columns, live filtering (Entry +
Combobox), read-only Text widget, <<TreeviewSelect>> and <Double-1> events, messagebox.

HOW THE SCAN LOOP WORKS (good viva question)
    Tkinter runs in ONE thread. If we scanned all files in a normal for-loop, the window would
    freeze until the loop ended. Instead _scan_batch() analyses files for ~50 milliseconds, then
    asks Tk to call it again with self.after(1, ...). Between calls Tk can redraw the window and
    respond to clicks, so the progress bar moves and the Stop button works.
"""
import time
import tkinter as tk
from tkinter import messagebox, ttk

from core import history, scanner
from ui.base import BasePage
from ui.details import FileDetailsWindow
from ui.theme import COLORS, LEVEL_TAG, build_tree, enable_sorting, font, make_card, style_level_tags

FILTER_ALL = "All levels"
FILTER_FLAGGED = "Flagged only (20+)"


class ResultsPage(BasePage):
    title = "Analysis Results"
    subtitle = "Findings, risk scores and evidence for every analysed file"

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # scan state
        self.results = []
        self.queue = []
        self.index = 0
        self.scanning = False
        self.stop_requested = False
        self.root_path = ""
        self.record = None
        self.started = 0.0
        self.threshold = 100
        self.truncated = False

        self.v_done = tk.StringVar(value="0")
        self.v_flagged = tk.StringVar(value="0")
        self.v_clean = tk.StringVar(value="0")
        self.v_errors = tk.StringVar(value="0")
        self.progress_text = tk.StringVar(value="No scan running.")
        self.search = tk.StringVar()
        self.level_filter = tk.StringVar(value=FILTER_ALL)

        # ---- Row 0: metric cards ----
        cards = ttk.Frame(self)
        cards.grid(row=0, column=0, sticky="ew", pady=(4, 0))
        specs = [("Files analysed", self.v_done, COLORS["primary"]), ("Flagged for review", self.v_flagged, "#c2410c"),
                 ("No significant flags", self.v_clean, "#1b7f3b"), ("Could not analyse", self.v_errors, "#5b6475")]
        for column, (title, var, accent) in enumerate(specs):
            cards.columnconfigure(column, weight=1, uniform="cards")
            make_card(cards, title, var, accent).grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0))

        # ---- Row 1: progress bar + Stop button ----
        progress_row = ttk.Frame(self)
        progress_row.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        progress_row.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_row, mode="determinate", maximum=1, value=0)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.stop_button = ttk.Button(progress_row, text="Stop", style="Danger.TButton", command=self.request_stop)
        self.stop_button.grid(row=0, column=1, padx=(10, 0))
        self.stop_button.state(["disabled"])
        ttk.Label(progress_row, textvariable=self.progress_text, style="Muted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # ---- Row 2: filters ----
        filters = ttk.Frame(self)
        filters.grid(row=2, column=0, sticky="ew", pady=(10, 6))
        ttk.Label(filters, text="Search:").pack(side="left")
        ttk.Entry(filters, textvariable=self.search, width=30).pack(side="left", padx=(6, 16))
        self.search.trace_add("write", lambda *args: self.rebuild_table())
        ttk.Label(filters, text="Assessment:").pack(side="left")
        box = ttk.Combobox(filters, textvariable=self.level_filter, state="readonly", width=22,
                           values=[FILTER_ALL, FILTER_FLAGGED] + scanner.ALL_LEVELS)
        box.pack(side="left", padx=6)
        box.bind("<<ComboboxSelected>>", lambda event: self.rebuild_table())
        ttk.Label(filters, text="Double-click a row for full details", style="Muted.TLabel").pack(side="right")

        # ---- Row 3: results table ----
        frame, self.tree = build_tree(self, [
            ("file", "File", 330, "w", True), ("type", "Detected type", 180, "w", False),
            ("size", "Size", 90, "e", False), ("score", "Score", 70, "center", False),
            ("level", "Assessment", 190, "w", False)], height=9)
        frame.grid(row=3, column=0, sticky="nsew")
        style_level_tags(self.tree)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda event: self.open_details())
        enable_sorting(self.tree, {
            "file": lambda i: self.results[int(i)]["relative"].lower(),
            "type": lambda i: self.results[int(i)]["detected_type"].lower(),
            "size": lambda i: self.results[int(i)]["size"],
            "score": lambda i: self.results[int(i)]["score"],
            "level": lambda i: self.results[int(i)]["score"]})

        # ---- Row 4: quick view (read-only Text widget) ----
        quick = ttk.LabelFrame(self, text="Quick view of the selected file", padding=8)
        quick.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        quick.columnconfigure(0, weight=1)
        self.quick_text = tk.Text(quick, height=5, wrap="word", relief="flat", bg=COLORS["surface"],
                                  fg=COLORS["text"], font=font(10), padx=8, pady=6, highlightthickness=0)
        self.quick_text.grid(row=0, column=0, sticky="ew")
        self.quick_text.tag_configure("bold", font=font(10, "bold"))
        self.quick_text.tag_configure("flag", foreground="#b42318")
        self.quick_text.tag_configure("muted", foreground=COLORS["muted"])
        self._set_quick_text([("Select a file in the table to see why it received its score.", "muted")])

        # ---- Row 5: buttons ----
        buttons = ttk.Frame(self)
        buttons.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(buttons, text="<  Back to Files", style="Secondary.TButton",
                   command=lambda: app.show_page("files")).pack(side="left")
        ttk.Button(buttons, text="View Full Details", style="Secondary.TButton", command=self.open_details).pack(side="left", padx=8)
        self.report_button = ttk.Button(buttons, text="Reports & PDF  >", style="Primary.TButton",
                                        command=lambda: app.show_page("reports"))
        self.report_button.pack(side="right")

    # --------------------------------------------------------------- public API
    def has_results(self) -> bool:
        return bool(self.results)

    def start_scan(self, files: list, root: str) -> None:
        """Begin analysing `files`. Called by the File Explorer."""
        if self.scanning:
            messagebox.showinfo("Scan running", "A scan is already in progress.")
            return
        self.results, self.queue, self.index = [], list(files), 0
        self.root_path = root
        self.record = None
        self.threshold = self.app.data.get_threshold()
        self.truncated = False
        self.scanning, self.stop_requested = True, False
        self.started = time.perf_counter()
        self.tree.delete(*self.tree.get_children())
        self._set_quick_text([("Scanning...", "muted")])
        self.progress.configure(maximum=max(1, len(self.queue)), value=0)
        self.stop_button.state(["!disabled"])
        self._update_cards()
        self.progress_text.set(f"Starting analysis of {len(self.queue)} file(s)...")
        self.app.set_status(f"Analysing {len(self.queue)} file(s) in {root}")
        self.after(20, self._scan_batch)

    def request_stop(self) -> None:
        self.stop_requested = True
        self.progress_text.set("Stopping after the current file...")

    def load_record(self, record: dict) -> None:
        """Show a finished scan from the history (used by the Reports page)."""
        if self.scanning:
            messagebox.showinfo("Scan running", "Wait for the current scan to finish first.")
            return
        self.results = record["results"]
        self.record = record
        self.root_path = record["root"]
        self.progress.configure(maximum=max(1, len(self.results)), value=len(self.results))
        self.progress_text.set(f"Loaded scan {record['report_id']} ({record['scanned_at']}) - {record['status']}.")
        self.rebuild_table()
        self._update_cards()
        self._set_quick_text([("Select a file in the table to see why it received its score.", "muted")])
        self.app.show_page("results")

    # ------------------------------------------------------------ the scan loop
    def _scan_batch(self) -> None:
        if not self.scanning:
            return
        if self.stop_requested:
            self._finish(stopped=True)
            return
        deadline = time.perf_counter() + 0.05                       # work for at most ~50 ms, then give control back to Tk
        while self.index < len(self.queue) and time.perf_counter() < deadline:
            path = self.queue[self.index]
            self.progress_text.set(f"Analysing {self.index + 1} of {len(self.queue)}:  {path.name}")
            self.results.append(scanner.analyze_file(path, root=self.root_path, threshold_mb=self.threshold))
            self.index += 1
            self._insert_row(len(self.results) - 1)
        self.progress["value"] = self.index
        self._update_cards()
        if self.index >= len(self.queue):
            self._finish(stopped=False)
        else:
            self.after(1, self._scan_batch)                         # schedule the next batch

    def _finish(self, stopped: bool) -> None:
        self.scanning = False
        self.stop_button.state(["disabled"])
        seconds = time.perf_counter() - self.started
        self._update_cards()
        self.rebuild_table()                                        # re-order: highest risk first
        if not self.results:
            self.progress_text.set("Scan stopped before any file was analysed.")
            return
        status = "Stopped early" if stopped else "Completed"
        self.record = history.new_record(self.root_path, self.results, self.threshold, self.app.data.recursive.get(),
                                         status, seconds)
        self.app.data.add_record(self.record)
        summary = self.record["summary"]
        self.progress_text.set(f"{status}: {summary['total']} file(s) in {seconds:.1f} s.  Highest score {summary['max_score']}/100 "
                               f"({summary['overall_level']}).  Report ID {self.record['report_id']}")
        self.app.set_status(f"Scan {status.lower()}: {summary['flagged']} of {summary['total']} file(s) flagged for review.")
        message = (f"{summary['total']} file(s) analysed in {seconds:.1f} s.\n\n"
                   f"Flagged for review: {summary['flagged']}\nHighest score: {summary['max_score']}/100 ({summary['overall_level']})\n\n"
                   "Open Reports to generate the PDF audit report?")
        if messagebox.askyesno(f"Scan {status.lower()}", message):
            self.app.show_page("reports")

    # --------------------------------------------------------------- table logic
    def _passes_filter(self, result: dict) -> bool:
        needle = self.search.get().strip().lower()
        if needle and needle not in result["relative"].lower() and needle not in result["detected_type"].lower():
            return False
        wanted = self.level_filter.get()
        if wanted == FILTER_ALL:
            return True
        if wanted == FILTER_FLAGGED:
            return not result["error"] and result["score"] >= scanner.FLAG_THRESHOLD
        return result["level"] == wanted

    def _insert_row(self, index: int) -> None:
        result = self.results[index]
        if not self._passes_filter(result):
            return
        self.tree.insert("", "end", iid=str(index), tags=(LEVEL_TAG[result["level"]],), values=(
            result["relative"], result["detected_type"], scanner.human_size(result["size"]),
            "-" if result["error"] else result["score"], result["level"]))
        if self.scanning:
            self.tree.see(str(index))                                # auto-scroll while scanning

    def rebuild_table(self) -> None:
        """Redraw the table. When no scan is running, show the riskiest files first."""
        self.tree.delete(*self.tree.get_children())
        order = range(len(self.results))
        if not self.scanning:
            order = sorted(order, key=lambda i: (-self.results[i]["score"], self.results[i]["relative"].lower()))
        for index in order:
            self._insert_row(index)
        self.tree.yview_moveto(0)

    def _update_cards(self) -> None:
        summary = scanner.summarise(self.results)
        self.v_done.set(f"{summary['total']}" + (f" / {len(self.queue)}" if self.scanning else ""))
        self.v_flagged.set(str(summary["flagged"]))
        self.v_clean.set(str(summary["clean"]))
        self.v_errors.set(str(summary["errors"]))

    # ------------------------------------------------------------ selection / details
    def _selected_result(self):
        selection = self.tree.selection()
        return self.results[int(selection[0])] if selection else None

    def _set_quick_text(self, parts: list) -> None:
        """Write (text, tag) pairs into the read-only Text widget."""
        self.quick_text.configure(state="normal")                    # must be 'normal' to change the text
        self.quick_text.delete("1.0", "end")
        for text, tag in parts:
            self.quick_text.insert("end", text, tag)
        self.quick_text.configure(state="disabled")                  # back to read-only

    def on_select(self, event=None) -> None:
        result = self._selected_result()
        if not result:
            return
        if result["error"]:
            self._set_quick_text([(result["relative"] + "\n", "bold"), ("Could not be analysed: " + result["error"], "flag")])
            return
        parts = [(f"{result['relative']}", "bold"), (f"   -   {result['score']}/100, {result['level']}\n", ""),
                 ("SHA-256: " + result["sha256"] + "\n", "muted")]
        flagged = [c for c in result["checks"] if c["status"] == "FLAG"]
        if flagged:
            for c in flagged:
                parts.append((f"+{c['points']}  {c['name']}: ", "flag"))
                parts.append((c["evidence"] + "\n", ""))
        else:
            parts.append(("No check was triggered for this file.", "muted"))
        self._set_quick_text(parts)

    def open_details(self) -> None:
        result = self._selected_result()
        if not result:
            messagebox.showinfo("No file selected", "Select a file in the table first.")
            return
        FileDetailsWindow(self.app, result)
