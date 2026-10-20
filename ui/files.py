"""
files.py - MODULE 3: File Explorer and Pre-Scan.

The files are only LISTED here (name, type, size). No security analysis happens until the
user presses "Analyse".

Tkinter concepts shown here: Entry with a live StringVar trace (search box), Combobox filter,
Spinbox + Checkbutton settings (IntVar / BooleanVar), Treeview with sortable columns and
scrollbars, <<TreeviewSelect>> event, dynamic button text.
"""
import tkinter as tk
from tkinter import messagebox, ttk

from core import scanner
from ui.base import BasePage
from ui.theme import build_tree, enable_sorting, font


class FilesPage(BasePage):
    title = "File Explorer"
    subtitle = "Review the files on the selected device, then run the analysis"

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.files = []                                          # every file found: list of dicts
        self.shown = []                                          # files currently visible after filtering

        self.search = tk.StringVar()
        self.type_filter = tk.StringVar(value="All types")
        self.summary = tk.StringVar()
        self.analyse_text = tk.StringVar(value="Analyse Files")
        self.selected_info = tk.StringVar(value="Select a file to see its details.")

        # ---- Row 0: target + settings ----
        top = ttk.LabelFrame(self, text="Target and scan settings", padding=10)
        top.grid(row=0, column=0, sticky="ew", pady=(4, 10))
        top.columnconfigure(0, weight=1)
        target_row = ttk.Frame(top)
        target_row.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 8))
        ttk.Label(target_row, text="Target:", font=font(10, "bold")).pack(side="left")
        ttk.Label(target_row, textvariable=app.data.selected_path).pack(side="left", padx=8)
        ttk.Label(top, text="Large-file threshold (MB):").grid(row=1, column=0, sticky="e", padx=(20, 6))
        # Spinbox: a number box with up/down arrows. textvariable ties it to the IntVar in AppData.
        ttk.Spinbox(top, from_=1, to=5000, width=6, textvariable=app.data.threshold_mb).grid(row=1, column=1)
        # Checkbutton: ties to a BooleanVar. command= runs whenever it is toggled.
        ttk.Checkbutton(top, text="Include sub-folders", variable=app.data.recursive,
                        command=self.load_folder).grid(row=1, column=2, padx=14)
        ttk.Button(top, text="Refresh", style="Secondary.TButton", command=self.load_folder).grid(row=1, column=3)

        # ---- Row 1: search + type filter ----
        filters = ttk.Frame(self)
        filters.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(filters, text="Search:").pack(side="left")
        ttk.Entry(filters, textvariable=self.search, width=34).pack(side="left", padx=(6, 18))
        # trace_add("write") calls our function EVERY time the text changes -> live filtering while typing.
        self.search.trace_add("write", lambda *args: self.apply_filters())
        ttk.Label(filters, text="File type:").pack(side="left")
        self.type_box = ttk.Combobox(filters, textvariable=self.type_filter, state="readonly", width=16, values=["All types"])
        self.type_box.pack(side="left", padx=6)
        self.type_box.bind("<<ComboboxSelected>>", lambda event: self.apply_filters())
        ttk.Label(filters, textvariable=self.summary, style="Muted.TLabel").pack(side="right")

        # ---- Row 2: file table ----
        frame, self.tree = build_tree(self, [
            ("name", "File name", 300, "w", True), ("type", "Type", 90, "center", False),
            ("size", "Size", 100, "e", False), ("modified", "Modified", 150, "center", False),
            ("folder", "Folder", 240, "w", True)], height=12)
        frame.grid(row=2, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        enable_sorting(self.tree, {                                # click a heading to sort by that column
            "name": lambda i: self.files[int(i)]["name"].lower(),
            "type": lambda i: self.files[int(i)]["type"],
            "size": lambda i: self.files[int(i)]["size"],
            "modified": lambda i: self.files[int(i)]["modified"],
            "folder": lambda i: self.files[int(i)]["folder"].lower()})

        # ---- Row 3: selected-file info + action buttons ----
        ttk.Label(self, textvariable=self.selected_info, style="Muted.TLabel").grid(row=3, column=0, sticky="w", pady=(8, 0))
        buttons = ttk.Frame(self)
        buttons.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(buttons, text="<  Back to Devices", style="Secondary.TButton",
                   command=lambda: app.show_page("devices")).pack(side="left")
        self.analyse_button = ttk.Button(buttons, textvariable=self.analyse_text, style="Primary.TButton",
                                         command=self.on_analyse)
        self.analyse_button.pack(side="right")

    # ------------------------------------------------------------ loading data
    def load_folder(self):
        """List the files of the selected folder (no analysis yet)."""
        target = self.app.data.selected_path.get()
        if not target:
            return
        self.configure(cursor="watch")
        self.app.set_status("Listing files...")
        self.update_idletasks()                                   # let Tk repaint before the (possibly slow) listing
        paths, truncated = scanner.list_files(target, recursive=self.app.data.recursive.get())
        self.files = []
        for path in paths:
            try:
                st = path.stat()
                size, modified = st.st_size, scanner.format_time(st.st_mtime)
            except OSError:
                size, modified = 0, "unknown"
            try:
                folder = str(path.parent.relative_to(target)) or "."
            except ValueError:
                folder = str(path.parent)
            self.files.append({"path": path, "name": path.name, "size": size, "modified": modified,
                               "type": path.suffix.lower().lstrip(".").upper() or "-", "folder": folder})
        self.configure(cursor="")
        types = sorted({f["type"] for f in self.files})
        self.type_box.configure(values=["All types"] + types)
        self.type_filter.set("All types")
        self.search.set("")
        self.apply_filters()
        if truncated:
            messagebox.showwarning("Large folder", f"Only the first {scanner.MAX_FILES} files are listed (safety limit).")
        self.app.set_status(f"Listed {len(self.files)} file(s) in {target}")

    def on_show(self):
        if self.app.data.selected_path.get() and not self.files:
            self.load_folder()

    def apply_filters(self):
        """Rebuild the table showing only rows that match the search text and the type filter."""
        needle = self.search.get().strip().lower()
        wanted = self.type_filter.get()
        self.tree.delete(*self.tree.get_children())
        self.shown = []
        total_size = 0
        for index, f in enumerate(self.files):
            if needle and needle not in f["name"].lower() and needle not in f["folder"].lower():
                continue
            if wanted != "All types" and f["type"] != wanted:
                continue
            self.shown.append(f)
            total_size += f["size"]
            self.tree.insert("", "end", iid=str(index), values=(f["name"], f["type"], scanner.human_size(f["size"]),
                                                                f["modified"], f["folder"]))
        self.summary.set(f"Showing {len(self.shown)} of {len(self.files)} files  |  {scanner.human_size(total_size)}")
        self.analyse_text.set(f"Analyse {len(self.shown)} File{'s' if len(self.shown) != 1 else ''}  >")
        self.analyse_button.state(["!disabled"] if self.shown else ["disabled"])

    def on_select(self, event=None):
        selection = self.tree.selection()
        if selection:
            f = self.files[int(selection[0])]
            self.selected_info.set(f"{f['path']}   |   {scanner.human_size(f['size'])}   |   modified {f['modified']}")

    def on_analyse(self):
        if not self.shown:
            messagebox.showwarning("Nothing to analyse", "No files match the current filters.")
            return
        if len(self.shown) > 2000 and not messagebox.askyesno("Large scan", f"{len(self.shown)} files will be analysed. This may take a while. Continue?"):
            return
        self.app.start_analysis([f["path"] for f in self.shown], self.app.data.selected_path.get())
