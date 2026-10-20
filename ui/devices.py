"""
devices.py - MODULE 2: Device Selection.

Tkinter concepts shown here: Treeview with a selection event (<<TreeviewSelect>>),
double-click binding, filedialog.askdirectory, Button state (enabled / disabled),
StringVar, messagebox.
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import devices, scanner
from ui.base import BasePage
from ui.theme import build_tree, font


class DevicesPage(BasePage):
    title = "Select Device"
    subtitle = "Choose the USB drive to inspect, or browse to any folder"

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.devices = []
        self.choice = tk.StringVar(value="No device selected")       # text shown under the table

        # ---- Toolbar ----
        toolbar = ttk.Frame(self)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(4, 10))
        ttk.Button(toolbar, text="Refresh Devices", style="Secondary.TButton", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="Browse Folder...", style="Secondary.TButton", command=self.browse_folder).pack(side="left", padx=8)
        ttk.Label(toolbar, text="Tip: use Browse Folder if your USB drive is not listed.", style="Muted.TLabel").pack(side="left", padx=12)

        # ---- Device table ----
        frame, self.tree = build_tree(self, [
            ("name", "Device / volume", 260, "w", True), ("path", "Path", 200, "w", True),
            ("kind", "Type", 140, "w", False), ("total", "Capacity", 100, "e", False),
            ("free", "Free space", 100, "e", False)], height=10)
        frame.grid(row=1, column=0, sticky="nsew")
        self.tree.tag_configure("removable", foreground="#1b7f3b")
        # Event bindings: <<TreeviewSelect>> fires when the selected row changes; <Double-1> is a double click.
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda event: self.continue_to_files())

        # ---- Footer: current choice + Continue button ----
        footer = ttk.Frame(self)
        footer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.choice, font=font(10, "bold")).grid(row=0, column=0, sticky="w")
        self.continue_button = ttk.Button(footer, text="Continue to Files  >", style="Primary.TButton",
                                          command=self.continue_to_files)
        self.continue_button.grid(row=0, column=1, sticky="e")
        self.continue_button.state(["disabled"])                  # disabled until a row is selected

    def on_show(self):
        self.refresh()

    def refresh(self):
        """Ask the operating system for connected drives and rebuild the table."""
        self.configure(cursor="watch")                           # show the 'busy' mouse pointer
        self.update_idletasks()
        self.devices = devices.list_devices()
        self.tree.delete(*self.tree.get_children())
        for index, device in enumerate(self.devices):
            self.tree.insert("", "end", iid=str(index), tags=("removable",) if device["removable"] else (),
                             values=(device["name"], device["path"], device["kind"],
                                     scanner.human_size(device["total"]), scanner.human_size(device["free"])))
        self.configure(cursor="")
        self.continue_button.state(["disabled"])
        self.choice.set("No device selected")
        count = sum(1 for d in self.devices if d["removable"])
        self.app.set_status(f"Found {len(self.devices)} drive(s), {count} removable. Green rows are USB / removable drives.")

    def on_select(self, event=None):
        selection = self.tree.selection()
        if selection:
            device = self.devices[int(selection[0])]
            self.choice.set(f"Selected: {device['name']}  ({device['path']})")
            self.continue_button.state(["!disabled"])             # enable the button

    def continue_to_files(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No device selected", "Select a device in the table first.")
            return
        self.app.set_target(self.devices[int(selection[0])]["path"])

    def browse_folder(self):
        """Open the operating system's own folder chooser."""
        folder = filedialog.askdirectory(title="Choose a folder or drive to scan", mustexist=True)
        if folder:                                               # empty string means the user cancelled
            self.app.set_target(folder)
