"""base.py - the parent class that all five pages (modules) inherit from."""
from tkinter import ttk


class BasePage(ttk.Frame):
    """Every module is a Frame that lives inside the main window's content area.

    title / subtitle : shown in the header bar when this page is displayed
    on_show()        : called every time the user navigates to the page (refresh data here)
    """
    title = ""
    subtitle = ""

    def __init__(self, parent, app):
        super().__init__(parent, padding=(24, 6, 24, 14))
        self.app = app          # reference to the main window so a page can navigate / share data

    def on_show(self):
        """Override in a subclass to refresh the page when it becomes visible."""
