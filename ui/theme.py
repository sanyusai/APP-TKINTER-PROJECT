"""
theme.py - colours, fonts, ttk styles and a few reusable widget builders.

Keeping the look of the application in ONE file means every page looks consistent
and the colours can be changed in a single place.
"""
import platform
import tkinter as tk
from tkinter import ttk

COLORS = {
    "bg": "#f4f6fb",            # page background
    "surface": "#ffffff",       # cards and tables
    "sidebar": "#17233c",
    "sidebar_hover": "#223356",
    "sidebar_active": "#2f6fed",
    "text": "#1d2433",
    "muted": "#6b7488",
    "border": "#dfe3ec",
    "primary": "#2f6fed",
    "primary_dark": "#2458c4",
    "danger": "#b42318",
}

# level name -> (strong colour for text, light colour for backgrounds)
LEVEL_STYLE = {
    "Low concern": ("#1b7f3b", "#e6f4ea"),
    "Review recommended": ("#9a6700", "#fff4d6"),
    "Elevated concern": ("#c2410c", "#ffe8d9"),
    "High concern": ("#b42318", "#fde7e5"),
    "Could not analyse": ("#5b6475", "#eceff4"),
}
LEVEL_TAG = {"Low concern": "low", "Review recommended": "review", "Elevated concern": "elevated",
             "High concern": "high", "Could not analyse": "error"}

_SYSTEM = platform.system()
FONT_FAMILY = {"Windows": "Segoe UI", "Darwin": "Helvetica Neue"}.get(_SYSTEM, "DejaVu Sans")
MONO_FAMILY = {"Windows": "Consolas", "Darwin": "Menlo"}.get(_SYSTEM, "DejaVu Sans Mono")


def font(size: int = 10, weight: str = "normal") -> tuple:
    """Return a Tk font tuple such as ('Segoe UI', 10, 'bold')."""
    return (FONT_FAMILY, size, weight)


def apply_theme(root: tk.Tk) -> None:
    """Configure every ttk widget style. ttk (themed Tk) styles are set once, here."""
    c = COLORS
    scale = max(1.0, root.winfo_fpixels("1i") / 96)       # 1.0 on normal screens, 1.5 on 150% Windows scaling
    style = ttk.Style(root)
    style.theme_use("clam")                               # 'clam' honours custom colours on Windows AND macOS

    style.configure(".", font=font(10), background=c["bg"], foreground=c["text"])
    style.configure("TFrame", background=c["bg"])
    style.configure("Card.TFrame", background=c["surface"])
    style.configure("Sidebar.TFrame", background=c["sidebar"])
    style.configure("TLabel", background=c["bg"], foreground=c["text"])
    style.configure("Muted.TLabel", foreground=c["muted"])
    style.configure("H1.TLabel", font=font(20, "bold"))
    style.configure("Sidebar.TLabel", background=c["sidebar"], foreground="#ffffff")
    style.configure("SidebarMuted.TLabel", background=c["sidebar"], foreground="#8fa0c4", font=font(9))
    style.configure("Status.TLabel", background="#e9edf5", foreground=c["muted"], padding=(12, 4), font=font(9))

    style.configure("TLabelframe", background=c["bg"], bordercolor=c["border"], relief="solid")
    style.configure("TLabelframe.Label", background=c["bg"], foreground=c["text"], font=font(10, "bold"))
    style.configure("TCheckbutton", background=c["bg"])
    style.map("TCheckbutton", background=[("active", c["bg"])])

    def button(name, bg, fg, active, disabled_bg="#c9d1e3"):
        style.configure(name, background=bg, foreground=fg, font=font(10, "bold"), padding=(16, 8),
                        borderwidth=0, focusthickness=0, focuscolor=bg, relief="flat", anchor="center")
        style.map(name, background=[("disabled", disabled_bg), ("active", active)],
                  foreground=[("disabled", "#ffffff")])

    button("Primary.TButton", c["primary"], "#ffffff", c["primary_dark"])
    button("Secondary.TButton", "#e3e8f3", c["text"], "#d3dbec", "#eef1f7")
    button("Danger.TButton", c["danger"], "#ffffff", "#8f1d14")
    style.configure("Secondary.TButton", font=font(10))
    style.map("Secondary.TButton", foreground=[("disabled", "#9aa3b8")])

    button("Nav.TButton", c["sidebar"], "#c9d3ea", c["sidebar_hover"])
    style.configure("Nav.TButton", anchor="w", padding=(22, 13), font=font(11))
    button("NavActive.TButton", c["sidebar_active"], "#ffffff", c["sidebar_active"])
    style.configure("NavActive.TButton", anchor="w", padding=(22, 13), font=font(11, "bold"))

    style.configure("Treeview", background=c["surface"], fieldbackground=c["surface"], foreground=c["text"],
                    rowheight=int(28 * scale), borderwidth=0, font=font(10))
    style.configure("Treeview.Heading", background="#eef1f7", foreground=c["text"], relief="flat",
                    font=font(10, "bold"), padding=(8, 6))
    style.map("Treeview", background=[("selected", c["primary"])], foreground=[("selected", "#ffffff")])
    style.map("Treeview.Heading", background=[("active", "#e1e7f3")])

    style.configure("TEntry", fieldbackground="#ffffff", padding=6)
    style.configure("TCombobox", fieldbackground="#ffffff", padding=5, arrowsize=14)
    style.configure("TSpinbox", fieldbackground="#ffffff", padding=5)
    style.configure("Horizontal.TProgressbar", troughcolor="#e1e7f3", background=c["primary"], thickness=14,
                    borderwidth=0, lightcolor=c["primary"], darkcolor=c["primary"])
    style.configure("TScrollbar", background="#d5dbe8", troughcolor=c["bg"], borderwidth=0, arrowcolor=c["muted"])


class AutoScrollbar(ttk.Scrollbar):
    """A scrollbar that hides itself when all rows already fit (cleaner look)."""

    def set(self, first, last):
        if float(first) <= 0.0 and float(last) >= 1.0:
            self.grid_remove()                      # everything is visible -> no scrollbar needed
        else:
            self.grid()                             # grid() remembers its old position
        super().set(first, last)


def make_card(parent, title: str, variable: tk.StringVar, accent: str, value_size: int = 22) -> tk.Frame:
    """A 'metric card': coloured accent bar, small title and a big number.
    Plain tk widgets are used here because they accept bg/fg colours directly."""
    c = COLORS
    card = tk.Frame(parent, bg=c["surface"], highlightbackground=c["border"], highlightthickness=1)
    tk.Frame(card, bg=accent, width=5).pack(side="left", fill="y")
    inner = tk.Frame(card, bg=c["surface"])
    inner.pack(side="left", fill="both", expand=True, padx=16, pady=12)
    tk.Label(inner, text=title, bg=c["surface"], fg=c["muted"], font=font(10)).pack(anchor="w")
    tk.Label(inner, textvariable=variable, bg=c["surface"], fg=c["text"], font=font(value_size, "bold")).pack(anchor="w")
    return card


def build_tree(parent, columns, height: int = 8, selectmode: str = "browse"):
    """Create a Treeview (table) with vertical + horizontal scrollbars.

    columns: list of (column_id, heading_text, width_in_pixels, alignment, stretch_when_resized)
    Returns (container_frame, tree). Place the container with grid()/pack(); use the tree for data.
    """
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=[col[0] for col in columns], show="headings", height=height,
                        selectmode=selectmode)
    y_scroll = AutoScrollbar(frame, orient="vertical", command=tree.yview)
    x_scroll = AutoScrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
    tree.grid(row=0, column=0, sticky="nsew")
    y_scroll.grid(row=0, column=1, sticky="ns")
    x_scroll.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    for column_id, heading, width, anchor, stretch in columns:
        tree.heading(column_id, text=heading, anchor=anchor)
        tree.column(column_id, width=width, minwidth=50, anchor=anchor, stretch=stretch)
    return frame, tree


def style_level_tags(tree: ttk.Treeview) -> None:
    """Colour table rows by risk level using Treeview 'tags'."""
    for level, tag in LEVEL_TAG.items():
        strong, light = LEVEL_STYLE[level]
        if tag == "low":                                       # most rows are low concern: keep them calm and readable
            tree.tag_configure(tag, foreground=COLORS["text"], background=COLORS["surface"])
        else:
            tree.tag_configure(tag, foreground=strong, background=light)


def enable_sorting(tree: ttk.Treeview, sort_keys: dict) -> None:
    """Make column headings clickable. sort_keys maps column_id -> function(row_id) -> value to sort by."""
    direction = {}

    def sort_by(column):
        reverse = direction.get(column, False)
        rows = sorted(tree.get_children(""), key=sort_keys[column], reverse=reverse)
        for position, row_id in enumerate(rows):
            tree.move(row_id, "", position)                  # re-insert rows in the new order
        direction[column] = not reverse

    for column in sort_keys:
        tree.heading(column, command=lambda col=column: sort_by(col))
