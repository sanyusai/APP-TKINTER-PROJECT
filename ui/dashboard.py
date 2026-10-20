"""
dashboard.py - MODULE 1: Home Dashboard.

Tkinter concepts shown here: Frame, Label, Button, grid() layout with weights,
StringVar, LabelFrame, Treeview, Canvas drawing, event binding (<Configure>).
"""
import tkinter as tk
from tkinter import ttk

from core import scanner
from ui.base import BasePage
from ui.theme import COLORS, LEVEL_STYLE, build_tree, font, make_card


class DashboardPage(BasePage):
    title = "Dashboard"
    subtitle = "Overview of your removable-media scans"

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # StringVars: the cards display these; we only call .set() to change what is shown.
        self.v_scans = tk.StringVar(value="0")
        self.v_files = tk.StringVar(value="0")
        self.v_flagged = tk.StringVar(value="0")
        self.v_last = tk.StringVar(value="-")

        # ---- Row 0: four metric cards (columns share the width equally) ----
        cards = ttk.Frame(self)
        cards.grid(row=0, column=0, sticky="ew", pady=(4, 0))
        specs = [("Total scans", self.v_scans, COLORS["primary"]), ("Files checked", self.v_files, "#7c4dff"),
                 ("Files flagged", self.v_flagged, "#c2410c"), ("Last scan", self.v_last, "#1b7f3b")]
        for column, (title, var, accent) in enumerate(specs):
            cards.columnconfigure(column, weight=1, uniform="cards")
            make_card(cards, title, var, accent, value_size=16 if title == "Last scan" else 22).grid(
                row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0))

        # ---- Row 1: recent scans table (left) + risk distribution chart (right) ----
        middle = ttk.Frame(self)
        middle.grid(row=1, column=0, sticky="nsew", pady=(16, 0))
        middle.columnconfigure(0, weight=3)
        middle.columnconfigure(1, weight=2)
        middle.rowconfigure(0, weight=1)

        recent = ttk.LabelFrame(middle, text="Recent scans", padding=10)
        recent.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        recent.rowconfigure(0, weight=1)
        recent.columnconfigure(0, weight=1)
        frame, self.recent_tree = build_tree(recent, [
            ("when", "Date / time", 135, "w", False), ("target", "Target", 110, "w", True),
            ("flagged", "Flagged", 100, "center", False), ("top", "Top score", 95, "center", False)], height=6)
        frame.grid(row=0, column=0, sticky="nsew")

        distribution = ttk.LabelFrame(middle, text="Risk distribution (latest scan)", padding=10)
        distribution.grid(row=0, column=1, sticky="nsew")
        distribution.rowconfigure(0, weight=1)
        distribution.columnconfigure(0, weight=1)
        # A Canvas lets us draw our own shapes (rectangles, text). Redraw whenever its size changes.
        self.canvas = tk.Canvas(distribution, bg=COLORS["surface"], highlightthickness=0, height=170)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.canvas.bind("<Configure>", lambda event: self._draw_distribution())

        # ---- Row 2: what the tool checks + the big "Start" button ----
        bottom = ttk.LabelFrame(self, text="What this tool checks (8 static checks, never executes files)", padding=12)
        bottom.grid(row=2, column=0, sticky="ew", pady=(16, 0))
        bottom.columnconfigure(0, weight=1)
        left_text = ("1  Extension / executable type\n2  Double extension (invoice.pdf.exe)\n"
                     "3  File signature vs. extension\n4  Metadata / file properties")
        right_text = ("5  Entropy (packed / encrypted data)\n6  PE header inspection (Windows .exe)\n"
                      "7  File size / empty-file check\n8  SHA-256 fingerprint  (then: 0-100 risk score)")
        ttk.Label(bottom, text=left_text, justify="left").grid(row=0, column=0, sticky="w")
        ttk.Label(bottom, text=right_text, justify="left").grid(row=0, column=1, sticky="w", padx=(30, 30))
        ttk.Button(bottom, text="Start New Scan  >", style="Primary.TButton",
                   command=lambda: app.show_page("devices")).grid(row=0, column=2, sticky="e")
        bottom.columnconfigure(1, weight=1)

    # ----------------------------------------------------------------- refresh
    def on_show(self):
        """Recalculate the cards and table from the scan history every time the page is shown."""
        records = self.app.data.history
        self.v_scans.set(str(len(records)))
        self.v_files.set(str(sum(r["summary"]["total"] for r in records)))
        self.v_flagged.set(str(sum(r["summary"]["flagged"] for r in records)))
        self.v_last.set(records[0]["scanned_at"][5:16] if records else "-")

        self.recent_tree.delete(*self.recent_tree.get_children())
        for record in records[:8]:
            s = record["summary"]
            self.recent_tree.insert("", "end", values=(record["scanned_at"][:16], record["root"], f"{s['flagged']} of {s['total']}", s["max_score"]))
        self._draw_distribution()

    def _draw_distribution(self):
        """Draw a horizontal bar for each risk level using Canvas shapes."""
        canvas = self.canvas
        canvas.delete("all")                                   # clear the old drawing
        width, height = canvas.winfo_width(), canvas.winfo_height()
        record = self.app.data.latest_record()
        if not record:
            canvas.create_text(width / 2, height / 2, text="No scans yet.\nRun a scan to see the risk distribution.",
                               fill=COLORS["muted"], font=font(11), justify="center")
            return
        counts = record["summary"]["by_level"]
        biggest = max(max(counts.values()), 1)
        row_height = max(24, (height - 8) / len(scanner.ALL_LEVELS))
        label_width, value_width = 150, 40
        bar_space = max(40, width - label_width - value_width - 10)
        for i, level in enumerate(scanner.ALL_LEVELS):
            y = 6 + i * row_height
            strong, light = LEVEL_STYLE[level]
            canvas.create_text(4, y + row_height / 2 - 2, text=level, anchor="w", fill=COLORS["text"], font=font(9))
            canvas.create_rectangle(label_width, y + 4, label_width + bar_space, y + row_height - 10, fill=light, outline="")
            count = counts.get(level, 0)
            if count:
                canvas.create_rectangle(label_width, y + 4, label_width + max(4, bar_space * count / biggest),
                                        y + row_height - 10, fill=strong, outline="")
            canvas.create_text(label_width + bar_space + 8, y + row_height / 2 - 2, text=str(count), anchor="w",
                               fill=COLORS["text"], font=font(10, "bold"))
