# Viva notes: explaining the Tkinter frontend

Everything the professor evaluates lives in the **`ui/`** folder. The **`core/`** folder is the security engine and has
**no Tkinter code**, so the frontend can be explained on its own.

## 1. The 30-second overview (say this first)

> "USB Security Auditor is a desktop application built with Tkinter. It has one main window with a sidebar and five pages:
> Dashboard, Device Selection, File Explorer, Analysis Results and Reports. Each page is a class that inherits from a Frame.
> All pages are created once and stacked in the same grid cell; clicking the sidebar raises one of them to the front with
> `tkraise()`. The scanning logic is separate in `core/scanner.py`; the GUI only calls it and displays the result."

## 2. Where each Tkinter concept is used

| Concept | File -> where | Viva answer |
|---------|---------------|-------------|
| **`tk.Tk()` root window** | `ui/app.py` -> `class App(tk.Tk)` | The main window. `App` inherits from `Tk`, so the window *is* the application. Title, size, minimum size and the close event are configured in `__init__`. |
| **`mainloop()`** | `main.py` | The event loop. It waits for clicks and key presses, calls our functions, and redraws the window. Nothing is clickable before it starts. |
| **`Frame` / `ttk.Frame`** | every page, `app.py` layout | A rectangular container used to group and arrange widgets. The sidebar, header, content area and each page are Frames. |
| **`Label`** | headers, cards (`theme.make_card`) | Displays text. With `textvariable=` it updates automatically when the variable changes. |
| **`Button`** | sidebar, *Analyse*, *Stop*, *Generate PDF* | Runs a function when clicked, using `command=`. Disabled buttons use `.state(["disabled"])`. |
| **`Entry`** | search boxes (`files.py`, `results.py`) | One-line text input. Tied to a `StringVar` with a *trace*, so the table filters on every keystroke. |
| **`Combobox`** | type filter, assessment filter | Drop-down list. `state="readonly"` stops free typing. The `<<ComboboxSelected>>` event triggers the filter. |
| **`Spinbox` + `IntVar`** | `files.py` (threshold in MB) | Number box with arrows, tied to an `IntVar` shared through `AppData`. |
| **`Checkbutton` + `BooleanVar`** | `files.py` (include sub-folders) | On/off option. `command=` reloads the file list when toggled. |
| **`Treeview`** | every table (`theme.build_tree`) | Themed widget for rows and columns. Columns are defined once; rows are added with `insert()`. Row ids (`iid`) link a row to its data. |
| **Scrollbar** | `theme.AutoScrollbar` | Linked both ways: the table's `yscrollcommand` moves the bar, the bar's `command` scrolls the table. My version hides itself when all rows fit. |
| **Tags (row colours)** | `theme.style_level_tags` | A tag is a named style (colour) given to rows. Each risk level has its own tag. |
| **Sortable columns** | `theme.enable_sorting` | Each heading gets a `command`; it sorts the rows and re-inserts them with `tree.move()`. |
| **`StringVar`, `IntVar`, `BooleanVar`** | `app.py` `AppData`, cards, filters | Observable variables. A widget bound to one updates automatically when `.set()` is called. |
| **`grid()`** | all pages | Row/column layout. `weight=1` lets a column or row stretch; `sticky="nsew"` makes a widget fill its cell. |
| **`pack()`** | toolbars, button rows | Stacks widgets in a line with `side="left"/"right"`. Used for simple rows; `grid` for the page layout. (Never mix both inside the same parent.) |
| **`tkraise()`** | `app.py` -> `show_page` | Brings one stacked page frame in front of the others. This is how navigation works with a single window. |
| **`LabelFrame`** | settings, quick view, tables | A Frame with a border and a title, for grouping related controls. |
| **`Canvas`** | `dashboard.py` -> `_draw_distribution` | A drawing surface. I draw the risk bars with `create_rectangle` and `create_text`, and redraw on the `<Configure>` (resize) event. |
| **`Text` (read-only)** | quick view (`results.py`), evidence (`details.py`) | Multi-line text with tags for bold/red. Set `state="normal"` to edit it in code, then `"disabled"` to make it read-only. |
| **`Progressbar`** | `results.py` | Determinate bar: `maximum` = number of files, `value` = files done. |
| **`Toplevel`** | `ui/details.py` | A second window. `transient(app)` keeps it above the main window; `<Escape>` closes it. |
| **`filedialog`** | `devices.py` (askdirectory), `reports.py` (asksaveasfilename) | The operating system's own folder chooser and Save-As box. They return an empty string if cancelled. |
| **`messagebox`** | everywhere | Pop-ups: `showinfo`, `showwarning`, `showerror`, and `askyesno` which returns True/False. |
| **Event binding** | `bind("<<TreeviewSelect>>")`, `<Double-1>`, `<Escape>`, `<Configure>` | `bind(event, function)` runs a function when an event happens, e.g. selecting a row or double-clicking. |
| **`after()`** | `results.py` -> `_scan_batch` | Schedules a function to run later *without freezing the window* (see section 3). |
| **`protocol("WM_DELETE_WINDOW")`** | `app.py` -> `on_close` | Replaces the default close behaviour so we can ask "A scan is running, quit anyway?". |
| **Themes / `ttk.Style`** | `theme.apply_theme` | All colours and fonts are in one place. The `clam` theme is used because it accepts custom colours on both Windows and macOS. |

## 3. The question most likely to be asked: "How does the scan not freeze the window?"

Tkinter has **one thread**. If I analysed every file inside a plain `for` loop, the window could not redraw or react to clicks
until the loop ended, so the progress bar would not move and *Stop* would not work.

Instead, `_scan_batch()` analyses files for about **50 milliseconds**, then calls `self.after(1, self._scan_batch)` and returns.
Tk gets control back, repaints the progress bar, handles any click (such as *Stop*), and then calls `_scan_batch` again.
This repeats until all files are done. It is *cooperative multitasking* without threads, which keeps the code simple.

## 4. Other likely questions

* **Why classes for pages?** Each page needs its own widgets *and* data (e.g. the results list). A class keeps them together,
  and all pages share `BasePage`, so adding a sixth page only needs a new subclass.
* **`pack` vs `grid` vs `place`?** `pack` = simple rows/columns, `grid` = table-like layout with stretch weights (used for pages),
  `place` = exact pixel positions (not used because it does not resize well).
* **`tk` vs `ttk`?** `ttk` widgets are themed and look native/consistent; plain `tk` widgets accept colours directly (used for cards).
* **How do pages share data?** Through `app.data` (`AppData`) which holds the selected path, settings and history. Each page receives the `app` object in its constructor.
* **How does the table show rows from different scans?** `iid` = the index into `self.results`; selecting a row reads `self.results[int(iid)]`.
* **What happens when a file cannot be read?** `analyze_file` catches `OSError` and returns a result with an `error`; the row shows "Could not analyse" and the scan continues.
* **Why does the PDF import happen inside a function?** So the app still starts if `reportlab` is not installed; the user then gets a clear message.

## 5. Security-logic answers (if asked)

* **Magic bytes:** the first bytes of a file identify its real format, e.g. `MZ` = Windows program, `%PDF-` = PDF, `PK` = ZIP/Office. A mismatch with the extension suggests a disguised file.
* **Double extension:** `invoice.pdf.exe` looks like a PDF because Windows hides known extensions, but the *last* extension decides how it opens.
* **Entropy:** Shannon entropy measures randomness from 0 to 8 bits per byte. Encrypted or packed data is close to 8; text is about 4-5. A high value is only a weak hint, so it is ignored for already-compressed types (zip, jpg, png).
* **PE header:** every Windows program starts with `MZ`; at offset `0x3C` is the position of `PE\0\0`, followed by the number of sections and flags. Broken values mean the file is not a real executable.
* **SHA-256:** a one-way fingerprint; any change in the file changes the hash completely. It identifies a file (for reputation lookups) but does not say whether it is malicious.
* **Why not "safe" / "malware"?** It is static, heuristic analysis. Labels such as *Review recommended* are honest about the limits.

## 6. Suggested 6-minute demo

1. **Dashboard (0:30):** point out the sidebar, cards and the chart, then press *Start New Scan*.
2. **Select Device (0:45):** *Refresh*, select the USB (or *Browse Folder*), explain the selection event, press *Continue*.
3. **File Explorer (1:00):** search, type filter, click a column heading to sort, set the threshold to 1 MB.
4. **Analyse (1:30):** watch the progress bar, then click the *High concern* row; show the quick view; double-click for the details window and copy the hash.
5. **Reports (1:00):** *Generate PDF Report*, open it and show the executive summary and one detailed finding.
6. **Code (1:00):** open `ui/app.py` (window + `tkraise`) and `ui/results.py` (`after()` loop).

Before presenting: run `python make_test_files.py`, test on the Windows laptop with a real USB stick, and copy a few of the sample files onto it.
