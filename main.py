"""
main.py - starts the USB Security Auditor.

Run with:   python main.py        (Windows)   |   python3 main.py   (macOS / Linux)
"""
import sys


def main() -> None:
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("Tkinter is not installed for this Python.\n"
              "  macOS (Homebrew):  brew install python-tk\n"
              "  Ubuntu/Debian:     sudo apt install python3-tk\n"
              "  Windows/macOS:     install Python from https://www.python.org (Tkinter is included)")
        sys.exit(1)

    if sys.platform.startswith("win"):                  # make the window sharp on high-DPI Windows screens
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass

    from ui.app import App
    App().mainloop()                                    # mainloop() = the event loop: wait for clicks, redraw, repeat


if __name__ == "__main__":
    main()
