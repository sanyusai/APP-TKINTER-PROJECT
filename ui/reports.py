"""
reports.py - MODULE 5: Reports and Scan History.

Tkinter concepts shown here: Treeview (history table), filedialog.asksaveasfilename (Save-As box),
messagebox (info / error / yes-no), busy cursor, enabling/disabling buttons based on selection.
"""
import csv
import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import history
from ui.base import BasePage
from ui.theme import build_tree


class ReportsPage(BasePage):
    title = "Reports & History"
    subtitle = "Review previous scans and export a corporate-style PDF audit report"

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.records = []
        self.detail = tk.StringVar(value="Select a scan in the table.")

        ttk.Label(self, text="Every completed scan is saved here. Choose one, then generate the PDF report or export the data as CSV.",
                  style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(4, 10))

        buttons = ttk.Frame(self)
        buttons.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.pdf_button = ttk.Button(buttons, text="Generate PDF Report", style="Primary.TButton", command=self.generate_pdf)
        self.pdf_button.pack(side="left")
        self.csv_button = ttk.Button(buttons, text="Export CSV", style="Secondary.TButton", command=self.export_csv)
        self.csv_button.pack(side="left", padx=8)
        self.open_button = ttk.Button(buttons, text="Open in Results", style="Secondary.TButton", command=self.open_in_results)
        self.open_button.pack(side="left")
        self.delete_button = ttk.Button(buttons, text="Delete Scan", style="Secondary.TButton", command=self.delete_record)
        self.delete_button.pack(side="right")
        self.action_buttons = [self.pdf_button, self.csv_button, self.open_button, self.delete_button]

        frame, self.tree = build_tree(self, [
            ("id", "Report ID", 190, "w", False), ("when", "Date / time", 140, "w", False),
            ("target", "Scanned target", 200, "w", True), ("files", "Files", 60, "center", False),
            ("flagged", "Flagged", 85, "center", False), ("score", "Top score", 95, "center", False),
            ("status", "Status", 110, "w", False)], height=10)
        frame.grid(row=2, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda event: self.open_in_results())

        ttk.Label(self, textvariable=self.detail, style="Muted.TLabel", wraplength=900, justify="left").grid(
            row=3, column=0, sticky="w", pady=(10, 0))

    # ----------------------------------------------------------------- data
    def on_show(self):
        self.refresh()
        # If a scan has just finished, pre-select it so "Generate PDF" is one click away.
        current = self.app.pages["results"].record
        if current and self.tree.exists("0") and self.app.data.history and self.app.data.history[0] is current:
            self.tree.selection_set("0")

    def refresh(self):
        self.records = self.app.data.history
        self.tree.delete(*self.tree.get_children())
        for index, record in enumerate(self.records):
            s = record["summary"]
            self.tree.insert("", "end", iid=str(index), values=(
                record["report_id"], record["scanned_at"][:16], record["root"], s["total"], s["flagged"], s["max_score"], record["status"]))
        self.on_select()

    def selected_record(self):
        selection = self.tree.selection()
        return self.records[int(selection[0])] if selection else None

    def on_select(self, event=None):
        record = self.selected_record()
        for button in self.action_buttons:
            button.state(["!disabled"] if record else ["disabled"])
        if not record:
            self.detail.set("No scan selected." if self.records else "No scans yet. Run a scan from the Dashboard to create your first report.")
            return
        s = record["summary"]
        levels = ", ".join(f"{count} {name.lower()}" for name, count in s["by_level"].items() if count)
        self.detail.set(f"{record['report_id']}  |  {record['root']}  |  {s['total']} files  |  overall: {s['overall_level']} "
                        f"({s['max_score']}/100)  |  {levels}")

    # -------------------------------------------------------------- actions
    def generate_pdf(self):
        record = self.selected_record()
        if not record:
            return
        try:
            from core import report_pdf                              # imported here so the app still starts without reportlab
        except ImportError:
            messagebox.showerror("PDF library missing", "The 'reportlab' package is required for PDF reports.\n\n"
                                 "Install it with:\n    pip install reportlab")
            return
        path = filedialog.asksaveasfilename(title="Save audit report", defaultextension=".pdf",
                                            initialfile=f"USB_Audit_Report_{record['report_id']}.pdf",
                                            filetypes=[("PDF document", "*.pdf")])
        if not path:                                                 # user pressed Cancel
            return
        self.configure(cursor="watch")
        self.update_idletasks()
        try:
            report_pdf.generate_pdf(record, path)
        except Exception as error:                                   # show any problem instead of crashing
            messagebox.showerror("Could not create PDF", f"{type(error).__name__}: {error}")
            return
        finally:
            self.configure(cursor="")
        self.app.set_status(f"PDF report saved: {path}")
        if messagebox.askyesno("Report created", f"The PDF report was saved to:\n{path}\n\nOpen it now?"):
            self._open_file(path)

    def export_csv(self):
        record = self.selected_record()
        if not record:
            return
        path = filedialog.asksaveasfilename(title="Export results as CSV", defaultextension=".csv",
                                            initialfile=f"USB_Audit_{record['report_id']}.csv",
                                            filetypes=[("CSV file", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:   # utf-8-sig so Excel reads accents correctly
                writer = csv.writer(handle)
                writer.writerow(["Report ID", "File", "Full path", "Detected type", "Size (bytes)", "SHA-256",
                                 "Score", "Assessment", "Flagged checks", "Evidence"])
                for r in record["results"]:
                    flagged = [c for c in r["checks"] if c["status"] == "FLAG"]
                    writer.writerow([record["report_id"], r["relative"], r["path"], r["detected_type"], r["size"], r["sha256"],
                                     "" if r["error"] else r["score"], r["level"], "; ".join(c["name"] for c in flagged),
                                     " | ".join(c["evidence"] for c in flagged) if flagged else (r["error"] or "")])
        except OSError as error:
            messagebox.showerror("Could not save CSV", str(error))
            return
        self.app.set_status(f"CSV saved: {path}")
        messagebox.showinfo("CSV exported", f"Saved {len(record['results'])} row(s) to:\n{path}")

    def open_in_results(self):
        record = self.selected_record()
        if record:
            self.app.pages["results"].load_record(record)

    def delete_record(self):
        record = self.selected_record()
        if record and messagebox.askyesno("Delete scan", f"Remove scan {record['report_id']} from the history?\n"
                                          "(Your scanned files are not touched.)"):
            self.app.data.history.remove(record)
            history.save_history(self.app.data.history)
            self.refresh()

    @staticmethod
    def _open_file(path: str):
        """Open a file with the operating system's default program."""
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)                                   # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except OSError as error:
            messagebox.showwarning("Could not open file", str(error))
