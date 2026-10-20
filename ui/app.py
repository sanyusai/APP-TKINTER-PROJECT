"""
app.py - the MAIN WINDOW of the application.

What this file does
    1. Creates the root window (tk.Tk) and applies the theme.
    2. Builds the permanent layout: sidebar (left), header + page area (right), status bar (bottom).
    3. Creates the five pages once and stacks them on top of each other.
    4. Shows one page at a time with tkraise() when the user clicks the sidebar.
    5. Holds the data shared by all pages (selected folder, settings, scan history).
"""
import tkinter as tk
from tkinter import messagebox, ttk

from core import history
from ui import theme
from ui.dashboard import DashboardPage
from ui.devices import DevicesPage
from ui.files import FilesPage
from ui.reports import ReportsPage
from ui.results import ResultsPage
from ui.theme import COLORS, font


class AppData:
    """Shared data. Tkinter variables (StringVar, IntVar, BooleanVar) are used so that
    widgets bound to them update automatically when the value changes."""

    def __init__(self):
        self.selected_path = tk.StringVar(value="")        # folder/drive chosen in Module 2
        self.threshold_mb = tk.IntVar(value=100)            # large-file threshold (Module 3 settings)
        self.recursive = tk.BooleanVar(value=True)          # include sub-folders?
        self.history = history.load_history()               # list of past scan records (newest first)

    def get_threshold(self) -> int:
        """The Spinbox can hold invalid text while the user types, so read it defensively."""
        try:
            return max(1, int(self.threshold_mb.get()))
        except (tk.TclError, ValueError):
            return 100

    def add_record(self, record: dict) -> None:
        self.history.insert(0, record)
        del self.history[history.MAX_RECORDS:]
        history.save_history(self.history)

    def latest_record(self):
        return self.history[0] if self.history else None


class App(tk.Tk):
    # (key, sidebar label, page class)
    PAGES = [
        ("dashboard", "1   Dashboard", DashboardPage),
        ("devices", "2   Select Device", DevicesPage),
        ("files", "3   File Explorer", FilesPage),
        ("results", "4   Analysis Results", ResultsPage),
        ("reports", "5   Reports & History", ReportsPage),
    ]

    def __init__(self):
        super().__init__()
        self.title("USB Security Auditor")
        self.configure(bg=COLORS["bg"])
        theme.apply_theme(self)
        self._set_geometry(1240, 780)
        self.minsize(1060, 680)

        self.data = AppData()
        self.status_text = tk.StringVar(value="Ready. Start a new scan from the Dashboard.")
        self.header_title = tk.StringVar()
        self.header_subtitle = tk.StringVar()
        self.pages = {}
        self.nav_buttons = {}
        self.current_page = None

        self._build_layout()
        self.show_page("dashboard")
        self.protocol("WM_DELETE_WINDOW", self.on_close)     # run our function when the X button is clicked

    # ------------------------------------------------------------ window setup
    def _set_geometry(self, width: int, height: int) -> None:
        """Open the window centred on screen (and never bigger than the screen)."""
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        width, height = min(width, screen_w - 60), min(height, screen_h - 100)
        x, y = (screen_w - width) // 2, max(0, (screen_h - height) // 3)
        self.geometry(f"{width}x{height}+{x}+{y}")           # "WIDTHxHEIGHT+X+Y"

    def _build_layout(self) -> None:
        # The window is a grid: column 0 = sidebar (fixed), column 1 = content (stretches).
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # ---- Sidebar (left) ----
        sidebar = ttk.Frame(self, style="Sidebar.TFrame", width=250)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)                         # keep the fixed width
        ttk.Label(sidebar, text="USB SECURITY", style="Sidebar.TLabel", font=font(17, "bold")).pack(anchor="w", padx=22, pady=(26, 0))
        ttk.Label(sidebar, text="AUDITOR", style="Sidebar.TLabel", font=font(17, "bold")).pack(anchor="w", padx=22)
        ttk.Label(sidebar, text="Removable media static analysis", style="SidebarMuted.TLabel").pack(anchor="w", padx=22, pady=(2, 26))
        for key, label, _page_class in self.PAGES:
            button = ttk.Button(sidebar, text=label, style="Nav.TButton", command=lambda k=key: self.navigate(k))
            button.pack(fill="x")
            self.nav_buttons[key] = button
        ttk.Label(sidebar, text="Files are only read,\nnever executed.", style="SidebarMuted.TLabel",
                  justify="left").pack(side="bottom", anchor="w", padx=22, pady=20)

        # ---- Right side: header + stacked pages ----
        right = ttk.Frame(self)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        header = ttk.Frame(right, padding=(24, 18, 24, 8))
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, textvariable=self.header_title, style="H1.TLabel").pack(anchor="w")
        ttk.Label(header, textvariable=self.header_subtitle, style="Muted.TLabel").pack(anchor="w")

        container = ttk.Frame(right)
        container.grid(row=1, column=0, sticky="nsew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)
        for key, _label, page_class in self.PAGES:
            page = page_class(container, self)
            page.grid(row=0, column=0, sticky="nsew")        # all pages share the SAME grid cell...
            self.pages[key] = page                           # ...and tkraise() decides which one is on top

        # ---- Status bar (bottom) ----
        ttk.Label(self, textvariable=self.status_text, style="Status.TLabel", anchor="w").grid(
            row=1, column=0, columnspan=2, sticky="ew")

    # --------------------------------------------------------------- navigation
    def show_page(self, key: str) -> None:
        """Bring one page to the front and highlight its sidebar button."""
        page = self.pages[key]
        page.tkraise()
        page.on_show()
        self.current_page = key
        self.header_title.set(page.title)
        self.header_subtitle.set(page.subtitle)
        for name, button in self.nav_buttons.items():
            button.configure(style="NavActive.TButton" if name == key else "Nav.TButton")

    def navigate(self, key: str) -> None:
        """Called by the sidebar. Checks that the user has done the earlier steps first."""
        if key == "files" and not self.data.selected_path.get():
            messagebox.showinfo("Select a device first", "Choose a USB drive or folder in step 2 before opening the file explorer.")
            key = "devices"
        elif key == "results" and not self.pages["results"].has_results():
            messagebox.showinfo("No analysis yet", "Run an analysis from the File Explorer first, "
                                "or open a past scan from Reports & History.")
            return
        self.show_page(key)

    def set_status(self, message: str) -> None:
        self.status_text.set(message)

    # ------------------------------------------------------------ shared actions
    def set_target(self, path: str) -> None:
        """Called by the Device page when the user chooses a drive or folder."""
        self.data.selected_path.set(path)
        self.pages["files"].load_folder()
        self.show_page("files")

    def start_analysis(self, files: list, root: str) -> None:
        """Called by the File Explorer: switch to the results page and start scanning."""
        self.show_page("results")
        self.pages["results"].start_scan(files, root)

    def on_close(self) -> None:
        if self.pages["results"].scanning:
            if not messagebox.askyesno("Scan in progress", "A scan is still running. Quit anyway?"):
                return
        self.destroy()
