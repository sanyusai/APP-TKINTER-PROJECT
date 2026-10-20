"""
details.py - the separate "File Details" window (a Toplevel).

Tkinter concepts shown here: Toplevel (a second window), transient(), LabelFrame, grid(),
read-only Entry, clipboard, Treeview row selection updating a Text widget, key binding (<Escape>).
"""
import tkinter as tk
from tkinter import ttk

from core import scanner
from ui.theme import COLORS, LEVEL_STYLE, MONO_FAMILY, build_tree, font


class FileDetailsWindow(tk.Toplevel):
    def __init__(self, app, result: dict):
        super().__init__(app)
        self.result = result
        self.title(f"File details - {result['name']}")
        self.configure(bg=COLORS["bg"])
        height = min(700, app.winfo_screenheight() - 90)
        self.geometry(f"900x{height}+{app.winfo_rootx() + 60}+{max(0, app.winfo_rooty() + 20)}")   # open near the main window
        self.minsize(760, 560)
        self.transient(app)                                   # keep this window on top of the main window
        self.bind("<Escape>", lambda event: self.destroy())   # Esc closes the window
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        strong, light = LEVEL_STYLE[result["level"]]

        # ---- Header: file name + coloured score badge ----
        header = tk.Frame(self, bg=COLORS["bg"], padx=20, pady=16)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        tk.Label(header, text=result["relative"], bg=COLORS["bg"], fg=COLORS["text"], font=font(15, "bold"),
                 anchor="w", justify="left", wraplength=620).grid(row=0, column=0, sticky="w")
        score_text = "n/a" if result["error"] else f"{result['score']}/100"
        tk.Label(header, text=f"{score_text}\n{result['level']}", bg=light, fg=strong, font=font(12, "bold"),
                 padx=18, pady=8).grid(row=0, column=1, sticky="e")

        # ---- File information (compact 2-row layout) ----
        info = ttk.LabelFrame(self, text="File information", padding=10)
        info.grid(row=1, column=0, sticky="ew", padx=20)
        info.columnconfigure(1, weight=1)
        ttk.Label(info, text="Full path:", font=font(10, "bold")).grid(row=0, column=0, sticky="nw", pady=2)
        ttk.Label(info, text=result["path"], wraplength=720, justify="left").grid(row=0, column=1, columnspan=3, sticky="w", padx=10, pady=2)
        summary = (f"Type: {result['detected_type']}      Size: {scanner.human_size(result['size'])}"
                   f"      Modified: {result['modified'] or '-'}")
        ttk.Label(info, text=summary).grid(row=1, column=0, columnspan=4, sticky="w", pady=2)
        ttk.Label(info, text="SHA-256:", font=font(10, "bold")).grid(row=2, column=0, sticky="w", pady=2)
        self.hash_var = tk.StringVar(value=result["sha256"] or "unavailable")
        # A read-only Entry lets the user select and copy the hash with the mouse.
        ttk.Entry(info, textvariable=self.hash_var, state="readonly", font=(MONO_FAMILY, 9)).grid(
            row=2, column=1, sticky="ew", padx=10, pady=2)
        self.copy_button = ttk.Button(info, text="Copy hash", style="Secondary.TButton", command=self.copy_hash)
        self.copy_button.grid(row=2, column=2, pady=2)

        # ---- Checks table + evidence text ----
        middle = ttk.LabelFrame(self, text="Security checks (click a row to read the evidence)", padding=10)
        middle.grid(row=2, column=0, sticky="nsew", padx=20, pady=(12, 0))
        middle.columnconfigure(0, weight=1)
        middle.rowconfigure(0, weight=1)
        frame, self.tree = build_tree(middle, [
            ("check", "Check", 290, "w", True), ("result", "Result", 90, "center", False),
            ("points", "Points", 70, "center", False)], height=6)
        frame.grid(row=0, column=0, sticky="nsew")
        self.tree.tag_configure("flag", foreground="#b42318", background="#fde7e5")
        status_names = {"FLAG": "Flagged", "PASS": "Passed", "INFO": "Info", "N/A": "N/A", "ERROR": "Error"}
        for index, c in enumerate(result["checks"]):
            self.tree.insert("", "end", iid=str(index), tags=("flag",) if c["status"] == "FLAG" else (),
                             values=(f"{c['number']}. {c['name']}" if c["number"] else c["name"],
                                     status_names.get(c["status"], c["status"]), f"+{c['points']}" if c["points"] else "0"))
        self.evidence = tk.Text(middle, height=3, wrap="word", relief="flat", bg="#f4f6fb", font=font(10),
                                padx=8, pady=6, highlightthickness=0, state="disabled")
        self.evidence.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.tree.bind("<<TreeviewSelect>>", self.show_evidence)
        flagged = [i for i, c in enumerate(result["checks"]) if c["status"] == "FLAG"]
        first = flagged[0] if flagged else (0 if result["checks"] else None)
        if first is not None:
            self.tree.selection_set(str(first))

        # ---- Recommendation + Close ----
        advice = ttk.LabelFrame(self, text="Recommended action", padding=10)
        advice.grid(row=3, column=0, sticky="ew", padx=20, pady=12)
        ttk.Label(advice, text=result["recommendation"], wraplength=800, justify="left").pack(anchor="w")
        ttk.Button(self, text="Close", style="Primary.TButton", command=self.destroy).grid(row=4, column=0, sticky="e", padx=20, pady=(0, 16))

    def show_evidence(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        check = self.result["checks"][int(selection[0])]
        self.evidence.configure(state="normal")
        self.evidence.delete("1.0", "end")
        self.evidence.insert("end", check["evidence"])
        self.evidence.configure(state="disabled")

    def copy_hash(self):
        self.clipboard_clear()
        self.clipboard_append(self.hash_var.get())
        self.copy_button.configure(text="Copied!")
        self.after(1500, lambda: self.copy_button.configure(text="Copy hash"))   # restore the label after 1.5 s
