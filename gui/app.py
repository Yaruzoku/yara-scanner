import json
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from yara_scanner.rules import (
    find_rule_files,
    compile_rules
)
from yara_scanner.scanner import scan_target


class YaraScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("YARA Scanner")
        self.geometry("1100x650")
        self.minsize(850, 680)
        self.resizable(True, True)

        # ==================================================
        # Theme
        # ==================================================

        self.dark_mode = tk.BooleanVar(value=False)

        self.rules_path = tk.StringVar()
        self.target_path = tk.StringVar()
        self.hash_all = tk.BooleanVar(value=False)

        self.rules = []
        self.current_results = []
        self.last_scan = None

        self.rule_entries = []

        self.scan_queue = queue.Queue()

        self.presets = {}
        self.preset_name = tk.StringVar()
        self.pending_preset_load = None

        if os.name == "nt":
            app_data = os.environ.get(
                "APPDATA",
                os.path.expanduser("~")
            )

            config_dir = os.path.join(
                app_data,
                "YARA Scanner"
            )

        else:
            config_dir = os.path.join(
                os.path.expanduser("~"),
                ".config",
                "YARA Scanner"
            )

        os.makedirs(
            config_dir,
            exist_ok=True
        )

        self.preset_file = os.path.join(
            config_dir,
            "presets.json"
        )

        self.load_presets()

        self.create_styles()
        self.create_scrollable_window()
        self.create_widgets()

        self.apply_theme()

        self.after(
            100,
            self.process_scan_queue
        )

    # ======================================================
    # Styles / Theme
    # ======================================================

    def create_styles(self):
        self.style = ttk.Style(self)

        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        try:
            self.style.configure(
                "TPanedwindow",
                sashwidth=8
            )
        except tk.TclError:
            pass

    def toggle_theme(self):
        self.dark_mode.set(
            not self.dark_mode.get()
        )

        self.apply_theme()

    def apply_theme(self):
        dark = self.dark_mode.get()

        if dark:
            self.colors = {
                "bg": "#1e1e1e",
                "surface": "#252526",
                "surface2": "#2d2d30",
                "fg": "#f1f1f1",
                "muted": "#bdbdbd",
                "border": "#444444",
                "entry": "#1e1e1e",
                "select": "#094771",
                "select_fg": "#ffffff",
                "button": "#333337",
                "button_active": "#45454a",
                "disabled": "#777777",
                "text": "#f1f1f1"
            }

        else:
            self.colors = {
                "bg": "#f0f0f0",
                "surface": "#ffffff",
                "surface2": "#f5f5f5",
                "fg": "#202020",
                "muted": "#606060",
                "border": "#c8c8c8",
                "entry": "#ffffff",
                "select": "#cce8ff",
                "select_fg": "#000000",
                "button": "#f5f5f5",
                "button_active": "#e5e5e5",
                "disabled": "#a0a0a0",
                "text": "#202020"
            }

        c = self.colors

        # --------------------------------------------------
        # Root / canvas
        # --------------------------------------------------

        self.configure(
            bg=c["bg"]
        )

        if hasattr(self, "main_canvas"):
            self.main_canvas.configure(
                bg=c["bg"],
                highlightbackground=c["bg"]
            )

        # --------------------------------------------------
        # General ttk
        # --------------------------------------------------

        self.style.configure(
            ".",
            background=c["bg"],
            foreground=c["fg"]
        )

        self.style.configure(
            "TFrame",
            background=c["bg"]
        )

        self.style.configure(
            "TLabel",
            background=c["bg"],
            foreground=c["fg"]
        )

        self.style.configure(
            "TLabelframe",
            background=c["bg"],
            foreground=c["fg"],
            bordercolor=c["border"]
        )

        self.style.configure(
            "TLabelframe.Label",
            background=c["bg"],
            foreground=c["fg"]
        )

        # --------------------------------------------------
        # Buttons
        # --------------------------------------------------

        self.style.configure(
            "TButton",
            background=c["button"],
            foreground=c["fg"],
            bordercolor=c["border"],
            lightcolor=c["button"],
            darkcolor=c["button"],
            focusthickness=1,
            padding=(8, 5)
        )

        self.style.map(
            "TButton",
            background=[
                ("active", c["button_active"]),
                ("pressed", c["button_active"]),
                ("disabled", c["surface2"])
            ],
            foreground=[
                ("disabled", c["disabled"])
            ]
        )

        # --------------------------------------------------
        # Entries
        # --------------------------------------------------

        self.style.configure(
            "TEntry",
            fieldbackground=c["entry"],
            foreground=c["fg"],
            bordercolor=c["border"],
            lightcolor=c["border"],
            darkcolor=c["border"]
        )

        self.style.map(
            "TEntry",
            fieldbackground=[
                ("disabled", c["surface2"])
            ],
            foreground=[
                ("disabled", c["disabled"])
            ]
        )

        # --------------------------------------------------
        # Combobox
        # --------------------------------------------------

        self.style.configure(
            "TCombobox",
            fieldbackground=c["entry"],
            background=c["button"],
            foreground=c["fg"],
            arrowcolor=c["fg"],
            bordercolor=c["border"],
            lightcolor=c["border"],
            darkcolor=c["border"]
        )

        self.style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", c["entry"]),
                ("disabled", c["surface2"])
            ],
            foreground=[
                ("disabled", c["disabled"])
            ],
            selectbackground=[
                ("readonly", c["select"])
            ],
            selectforeground=[
                ("readonly", c["select_fg"])
            ]
        )

        self.option_add(
            "*TCombobox*Listbox.background",
            c["entry"]
        )

        self.option_add(
            "*TCombobox*Listbox.foreground",
            c["fg"]
        )

        self.option_add(
            "*TCombobox*Listbox.selectBackground",
            c["select"]
        )

        self.option_add(
            "*TCombobox*Listbox.selectForeground",
            c["select_fg"]
        )

        # --------------------------------------------------
        # Checkbuttons
        # --------------------------------------------------

        self.style.configure(
            "TCheckbutton",
            background=c["bg"],
            foreground=c["fg"]
        )

        self.style.map(
            "TCheckbutton",
            background=[
                ("active", c["bg"])
            ],
            foreground=[
                ("disabled", c["disabled"])
            ]
        )

        # --------------------------------------------------
        # Treeviews
        # --------------------------------------------------

        self.style.configure(
            "Treeview",
            background=c["surface"],
            foreground=c["fg"],
            fieldbackground=c["surface"],
            bordercolor=c["border"],
            lightcolor=c["border"],
            darkcolor=c["border"],
            rowheight=25
        )

        self.style.map(
            "Treeview",
            background=[
                ("selected", c["select"])
            ],
            foreground=[
                ("selected", c["select_fg"])
            ]
        )

        self.style.configure(
            "Treeview.Heading",
            background=c["surface2"],
            foreground=c["fg"],
            bordercolor=c["border"],
            lightcolor=c["border"],
            darkcolor=c["border"],
            relief="flat"
        )

        self.style.map(
            "Treeview.Heading",
            background=[
                ("active", c["button_active"])
            ],
            foreground=[
                ("active", c["fg"])
            ]
        )

        # --------------------------------------------------
        # Scrollbars
        # --------------------------------------------------

        self.style.configure(
            "TScrollbar",
            background=c["button"],
            troughcolor=c["surface2"],
            bordercolor=c["border"],
            lightcolor=c["button"],
            darkcolor=c["button"],
            arrowcolor=c["fg"]
        )

        self.style.map(
            "TScrollbar",
            background=[
                ("active", c["button_active"]),
                ("pressed", c["button_active"])
            ]
        )

        # --------------------------------------------------
        # Paned windows
        # --------------------------------------------------

        self.style.configure(
            "TPanedwindow",
            background=c["border"]
        )

        # --------------------------------------------------
        # Progress bars
        # --------------------------------------------------

        self.style.configure(
            "Horizontal.TProgressbar",
            background=c["select"],
            troughcolor=c["surface2"],
            bordercolor=c["border"],
            lightcolor=c["select"],
            darkcolor=c["select"]
        )

        self.style.configure(
            "Green.Horizontal.TProgressbar",
            background="#4caf50",
            troughcolor=c["surface2"],
            bordercolor=c["border"],
            lightcolor="#4caf50",
            darkcolor="#4caf50"
        )

        # --------------------------------------------------
        # Text widgets
        # --------------------------------------------------

        for widget in (
            getattr(self, "details", None),
            getattr(self, "rule_details", None)
        ):

            if widget is None:
                continue

            widget.configure(
                background=c["surface"],
                foreground=c["text"],
                insertbackground=c["fg"],
                selectbackground=c["select"],
                selectforeground=c["select_fg"]
            )

        # --------------------------------------------------
        # Theme button
        # --------------------------------------------------

        if hasattr(self, "theme_button"):
            self.theme_button.configure(
                text="☀ Light"
                if dark
                else "🌙 Dark"
            )

    # ======================================================
    # Scrollable main window
    # ======================================================

    def create_scrollable_window(self):
        outer = ttk.Frame(self)

        outer.pack(
            fill="both",
            expand=True
        )

        self.main_canvas = tk.Canvas(
            outer,
            highlightthickness=0
        )

        self.main_canvas.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar = ttk.Scrollbar(
            outer,
            orient="vertical",
            command=self.main_canvas.yview
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.main_canvas.configure(
            yscrollcommand=scrollbar.set
        )

        self.main_frame = ttk.Frame(
            self.main_canvas,
            padding=15
        )

        self.canvas_window = self.main_canvas.create_window(
            (0, 0),
            window=self.main_frame,
            anchor="nw"
        )

        self.main_frame.bind(
            "<Configure>",
            self.update_scroll_region
        )

        self.main_canvas.bind(
            "<Configure>",
            self.resize_scrollable_frame
        )

        self.bind_all(
            "<MouseWheel>",
            self.on_mousewheel,
            add="+"
        )

    def update_scroll_region(self, event=None):
        self.main_canvas.configure(
            scrollregion=self.main_canvas.bbox("all")
        )

    def resize_scrollable_frame(self, event):
        self.main_canvas.itemconfigure(
            self.canvas_window,
            width=event.width
        )

    def on_mousewheel(self, event):
        widget = event.widget
        current = widget

        while current is not None:
            if current in (
                getattr(self, "results", None),
                getattr(self, "rule_tree", None),
                getattr(self, "details", None),
                getattr(self, "rule_details", None)
            ):
                return

            try:
                current = current.master
            except AttributeError:
                break

        self.main_canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )

    # ======================================================
    # Main UI
    # ======================================================

    def create_widgets(self):
        main = self.main_frame

        # --------------------------------------------------
        # Title
        # --------------------------------------------------

        title_frame = ttk.Frame(main)

        title_frame.pack(
            fill="x",
            pady=(0, 12)
        )

        ttk.Label(
            title_frame,
            text="YARA Scanner",
            font=("Segoe UI", 20, "bold")
        ).pack(
            side="left"
        )

        self.theme_button = ttk.Button(
            title_frame,
            text="🌙 Dark",
            command=self.toggle_theme
        )

        self.theme_button.pack(
            side="right"
        )

        # --------------------------------------------------
        # Rules directory
        # --------------------------------------------------

        ttk.Label(
            main,
            text="Rules directory:"
        ).pack(
            anchor="w"
        )

        rules_frame = ttk.Frame(main)

        rules_frame.pack(
            fill="x",
            pady=(3, 10)
        )

        ttk.Entry(
            rules_frame,
            textvariable=self.rules_path
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        ttk.Button(
            rules_frame,
            text="Browse...",
            command=self.browse_rules
        ).pack(
            side="left",
            padx=(8, 0)
        )

        # --------------------------------------------------
        # Target
        # --------------------------------------------------

        ttk.Label(
            main,
            text="Target:"
        ).pack(
            anchor="w"
        )

        target_frame = ttk.Frame(main)

        target_frame.pack(
            fill="x",
            pady=(3, 10)
        )

        ttk.Entry(
            target_frame,
            textvariable=self.target_path
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        ttk.Button(
            target_frame,
            text="File...",
            command=self.browse_file
        ).pack(
            side="left",
            padx=(8, 4)
        )

        ttk.Button(
            target_frame,
            text="Folder...",
            command=self.browse_folder
        ).pack(
            side="left"
        )

        # --------------------------------------------------
        # Options
        # --------------------------------------------------

        options_frame = ttk.LabelFrame(
            main,
            text="Options",
            padding=10
        )

        options_frame.pack(
            fill="x",
            pady=(0, 10)
        )

        ttk.Checkbutton(
            options_frame,
            text="Calculate SHA-256 for clean files",
            variable=self.hash_all
        ).pack(
            anchor="w"
        )

        # ==================================================
        # Rule Management
        # ==================================================

        rule_manager = ttk.LabelFrame(
            main,
            text="Rule Management",
            padding=8
        )

        rule_manager.pack(
            fill="x",
            pady=(0, 12)
        )

        # --------------------------------------------------
        # Rule toolbar
        # --------------------------------------------------

        rule_toolbar = ttk.Frame(
            rule_manager
        )

        rule_toolbar.pack(
            fill="x",
            pady=(0, 8)
        )

        self.rule_search = tk.StringVar()

        search_entry = ttk.Entry(
            rule_toolbar,
            textvariable=self.rule_search
        )

        search_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.rule_search.trace_add(
            "write",
            self.filter_rules
        )

        ttk.Button(
            rule_toolbar,
            text="Enable All",
            command=self.enable_all_rules
        ).pack(
            side="left",
            padx=(8, 0)
        )

        ttk.Button(
            rule_toolbar,
            text="Disable All",
            command=self.disable_all_rules
        ).pack(
            side="left",
            padx=(4, 0)
        )

        ttk.Button(
            rule_toolbar,
            text="Refresh",
            command=self.refresh_rules
        ).pack(
            side="left",
            padx=(4, 0)
        )

        self.rule_count_label = ttk.Label(
            rule_toolbar,
            text="No rules loaded"
        )

        self.rule_count_label.pack(
            side="left",
            padx=(12, 0)
        )

        # --------------------------------------------------
        # Presets
        # --------------------------------------------------

        preset_frame = ttk.Frame(
            rule_manager
        )

        preset_frame.pack(
            fill="x",
            pady=(0, 8)
        )

        ttk.Label(
            preset_frame,
            text="Presets:"
        ).pack(
            side="left"
        )

        self.preset_combo = ttk.Combobox(
            preset_frame,
            textvariable=self.preset_name,
            state="readonly",
            width=25
        )

        self.preset_combo.pack(
            side="left",
            padx=(6, 4)
        )

        ttk.Button(
            preset_frame,
            text="Load",
            command=self.load_preset
        ).pack(
            side="left",
            padx=(0, 4)
        )

        ttk.Button(
            preset_frame,
            text="Save",
            command=self.save_preset
        ).pack(
            side="left",
            padx=(0, 4)
        )

        ttk.Button(
            preset_frame,
            text="Delete",
            command=self.delete_preset
        ).pack(
            side="left",
            padx=(0, 4)
        )

        ttk.Button(
            preset_frame,
            text="Reset",
            command=self.reset_rules
        ).pack(
            side="left"
        )

        self.update_preset_dropdown()

        # --------------------------------------------------
        # Rule list / details splitter
        # --------------------------------------------------

        self.rule_paned = ttk.PanedWindow(
            rule_manager,
            orient="horizontal"
        )

        self.rule_paned.pack(
            fill="both",
            expand=True
        )

        # --------------------------------------------------
        # Rule list
        # --------------------------------------------------

        rule_list_frame = ttk.Frame(
            self.rule_paned
        )

        self.rule_paned.add(
            rule_list_frame,
            weight=1
        )

        rule_list_frame.grid_rowconfigure(
            0,
            weight=1
        )

        rule_list_frame.grid_columnconfigure(
            0,
            weight=1
        )

        rule_columns = (
            "enabled",
            "name",
            "source",
            "tags"
        )

        self.rule_tree = ttk.Treeview(
            rule_list_frame,
            columns=rule_columns,
            show="headings",
            selectmode="browse"
        )

        self.rule_tree.heading(
            "enabled",
            text="✓"
        )

        self.rule_tree.heading(
            "name",
            text="Rule"
        )

        self.rule_tree.heading(
            "source",
            text="Source"
        )

        self.rule_tree.heading(
            "tags",
            text="Tags"
        )

        self.rule_tree.column(
            "enabled",
            width=40,
            minwidth=40,
            stretch=False,
            anchor="center"
        )

        self.rule_tree.column(
            "name",
            width=180,
            minwidth=100,
            stretch=True
        )

        self.rule_tree.column(
            "source",
            width=150,
            minwidth=100,
            stretch=True
        )

        self.rule_tree.column(
            "tags",
            width=100,
            minwidth=70,
            stretch=True
        )

        self.rule_tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        rule_vertical = ttk.Scrollbar(
            rule_list_frame,
            orient="vertical",
            command=self.rule_tree.yview
        )

        rule_vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        rule_horizontal = ttk.Scrollbar(
            rule_list_frame,
            orient="horizontal",
            command=self.rule_tree.xview
        )

        rule_horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        self.rule_tree.configure(
            yscrollcommand=rule_vertical.set,
            xscrollcommand=rule_horizontal.set
        )

        self.rule_tree.bind(
            "<<TreeviewSelect>>",
            self.show_rule_details
        )

        self.rule_tree.bind(
            "<Button-1>",
            self.handle_rule_click
        )

        # --------------------------------------------------
        # Rule details
        # --------------------------------------------------

        rule_details_frame = ttk.Frame(
            self.rule_paned
        )

        self.rule_paned.add(
            rule_details_frame,
            weight=2
        )

        rule_details_frame.grid_rowconfigure(
            0,
            weight=1
        )

        rule_details_frame.grid_columnconfigure(
            0,
            weight=1
        )

        self.rule_details = tk.Text(
            rule_details_frame,
            wrap="none",
            font=("Consolas", 9)
        )

        self.rule_details.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        rule_details_vertical = ttk.Scrollbar(
            rule_details_frame,
            orient="vertical",
            command=self.rule_details.yview
        )

        rule_details_vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        rule_details_horizontal = ttk.Scrollbar(
            rule_details_frame,
            orient="horizontal",
            command=self.rule_details.xview
        )

        rule_details_horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        self.rule_details.configure(
            yscrollcommand=rule_details_vertical.set,
            xscrollcommand=rule_details_horizontal.set
        )

        self.rule_details.config(
            state="disabled"
        )

        rule_manager.configure(
            height=260
        )

        rule_manager.pack_propagate(False)

        self.after(
            200,
            self.fit_rule_columns
        )

        # ==================================================
        # Scan / Export buttons
        # ==================================================

        buttons_frame = ttk.Frame(
            main
        )

        buttons_frame.pack(
            fill="x",
            pady=(0, 8)
        )

        self.scan_button = ttk.Button(
            buttons_frame,
            text="SCAN",
            command=self.start_scan
        )

        self.scan_button.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.export_button = ttk.Button(
            buttons_frame,
            text="Export JSON",
            command=self.export_json,
            state="disabled"
        )

        self.export_button.pack(
            side="left",
            padx=(8, 0)
        )

        # ==================================================
        # Progress
        # ==================================================

        progress_frame = ttk.Frame(
            main
        )

        progress_frame.pack(
            fill="x",
            pady=(0, 10)
        )

        self.progress = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            maximum=1,
            value=0
        )

        self.progress.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.status = ttk.Label(
            progress_frame,
            text="Ready"
        )

        self.status.pack(
            side="left",
            padx=(10, 0)
        )

        # ==================================================
        # Results / Details splitter
        # ==================================================

        self.paned = ttk.PanedWindow(
            main,
            orient="vertical"
        )

        self.paned.pack(
            fill="x",
            expand=False
        )

        # --------------------------------------------------
        # Results
        # --------------------------------------------------

        results_frame = ttk.LabelFrame(
            self.paned,
            text="Results",
            padding=8
        )

        self.paned.add(
            results_frame,
            weight=3
        )

        results_frame.grid_rowconfigure(
            0,
            weight=1
        )

        results_frame.grid_columnconfigure(
            0,
            weight=1
        )

        result_columns = (
            "file",
            "status",
            "rules"
        )

        self.results = ttk.Treeview(
            results_frame,
            columns=result_columns,
            show="headings",
            selectmode="browse"
        )

        self.results.heading(
            "file",
            text="File"
        )

        self.results.heading(
            "status",
            text="Status"
        )

        self.results.heading(
            "rules",
            text="Rules triggered"
        )

        self.results.column(
            "file",
            width=600,
            minwidth=180,
            stretch=True
        )

        self.results.column(
            "status",
            width=110,
            minwidth=70,
            stretch=False,
            anchor="center"
        )

        self.results.column(
            "rules",
            width=130,
            minwidth=80,
            stretch=False,
            anchor="center"
        )

        self.results.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        results_vertical = ttk.Scrollbar(
            results_frame,
            orient="vertical",
            command=self.results.yview
        )

        results_vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        results_horizontal = ttk.Scrollbar(
            results_frame,
            orient="horizontal",
            command=self.results.xview
        )

        results_horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        self.results.configure(
            yscrollcommand=results_vertical.set,
            xscrollcommand=results_horizontal.set
        )

        self.results.tag_configure(
            "match",
            foreground="#c62828"
        )

        self.results.tag_configure(
            "clean",
            foreground="#2e7d32"
        )

        self.results.tag_configure(
            "failed",
            foreground="#ef6c00"
        )

        self.results.bind(
            "<<TreeviewSelect>>",
            self.show_details
        )

        # --------------------------------------------------
        # Match details
        # --------------------------------------------------

        details_frame = ttk.LabelFrame(
            self.paned,
            text="Match Details",
            padding=8
        )

        self.paned.add(
            details_frame,
            weight=2
        )

        details_frame.grid_rowconfigure(
            0,
            weight=1
        )

        details_frame.grid_columnconfigure(
            0,
            weight=1
        )

        self.details = tk.Text(
            details_frame,
            wrap="none",
            font=("Consolas", 9)
        )

        self.details.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        details_vertical = ttk.Scrollbar(
            details_frame,
            orient="vertical",
            command=self.details.yview
        )

        details_vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        details_horizontal = ttk.Scrollbar(
            details_frame,
            orient="horizontal",
            command=self.details.xview
        )

        details_horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        self.details.configure(
            yscrollcommand=details_vertical.set,
            xscrollcommand=details_horizontal.set
        )

        self.details.config(
            state="disabled"
        )

        # Smaller default results section.
        results_frame.configure(
            height=50
        )

        details_frame.configure(
            height=110
        )

        results_frame.pack_propagate(False)
        details_frame.pack_propagate(False)

        # --------------------------------------------------
        # Summary
        # --------------------------------------------------

        self.summary = ttk.Label(
            main,
            text=(
                "Files: 0    "
                "Matches: 0    "
                "Rules triggered: 0    "
                "Failed: 0"
            )
        )

        self.summary.pack(
            anchor="w",
            pady=(10, 0)
        )

        self.after(
            100,
            self.set_initial_splitters
        )

    # ======================================================
    # Splitters
    # ======================================================

    def set_initial_splitters(self):
        try:
            width = self.rule_paned.winfo_width()

            if width > 200:
                self.rule_paned.sashpos(
                    0,
                    int(width * 0.34)
                )

        except tk.TclError:
            pass

        try:
            height = self.paned.winfo_height()

            if height > 150:
                self.paned.sashpos(
                    0,
                    int(height * 0.20)
                )

        except tk.TclError:
            pass

        self.after(
            100,
            self.fit_rule_columns
        )

    def fit_rule_columns(self):
        if not hasattr(
            self,
            "rule_tree"
        ):
            return

        width = self.rule_tree.winfo_width()

        if width <= 0:
            return

        available = max(
            width - 44,
            300
        )

        self.rule_tree.column(
            "enabled",
            width=40
        )

        self.rule_tree.column(
            "name",
            width=max(
                int(available * 0.25),
                100
            )
        )

        self.rule_tree.column(
            "source",
            width=max(
                int(available * 0.25),
                100
            )
        )

        self.rule_tree.column(
            "tags",
            width=max(
                int(available * 0.50),
                100
            )
        )

    # ======================================================
    # Rule management
    # ======================================================

    def refresh_rules(self):
        rules_path = self.rules_path.get().strip()

        if not rules_path:
            return

        if not os.path.isdir(rules_path):
            messagebox.showerror(
                "Invalid rules directory",
                "The selected rules directory does not exist."
            )

            return

        self.status.config(
            text="Loading YARA rules..."
        )

        self.rule_search.set("")

        thread = threading.Thread(
            target=self.load_rules_background,
            args=(rules_path,),
            daemon=True
        )

        thread.start()

    def load_rules_background(
        self,
        rules_path
    ):
        try:
            rule_files = find_rule_files(
                rules_path
            )

            rules, errors = compile_rules(
                rule_files
            )

            self.scan_queue.put(
                (
                    "rules_loaded",
                    rules,
                    errors
                )
            )

        except Exception as error:
            self.scan_queue.put(
                (
                    "rules_error",
                    str(error)
                )
            )

    def populate_rule_manager(self):
        previous_states = {
            (
                rule["source"],
                rule["name"]
            ): rule["enabled"]
            for rule in self.rule_entries
        }

        for item in self.rule_tree.get_children():
            self.rule_tree.delete(item)

        self.rule_entries = []

        for rule_set in self.rules:

            source = rule_set["file"]

            for rule in rule_set["compiled"]:

                key = (
                    source,
                    rule.identifier
                )

                entry = {
                    "name": rule.identifier,
                    "source": source,
                    "tags": list(rule.tags),
                    "meta": dict(rule.meta),
                    "enabled": previous_states.get(
                        key,
                        True
                    )
                }

                self.rule_entries.append(
                    entry
                )

        self.update_rule_count()

        self.filter_rules()

    def update_rule_count(self):
        total = len(
            self.rule_entries
        )

        enabled = sum(
            1
            for rule in self.rule_entries
            if rule["enabled"]
        )

        if total == 0:

            self.rule_count_label.config(
                text="No rules loaded"
            )

        else:

            self.rule_count_label.config(
                text=(
                    f"{enabled}/{total} rules enabled"
                )
            )

    def filter_rules(
        self,
        *args
    ):
        search = self.rule_search.get().strip().lower()

        for item in self.rule_tree.get_children():
            self.rule_tree.delete(item)

        for index, rule in enumerate(
            self.rule_entries
        ):

            name = rule["name"]
            source = rule["source"]
            tags = rule["tags"]

            searchable = " ".join([
                name,
                source,
                " ".join(tags)
            ]).lower()

            if search and search not in searchable:
                continue

            enabled_marker = (
                "✓"
                if rule["enabled"]
                else ""
            )

            self.rule_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    enabled_marker,
                    name,
                    os.path.basename(source),
                    ", ".join(tags)
                )
            )

        self.update_rule_count()

    def handle_rule_click(
        self,
        event
    ):
        region = self.rule_tree.identify(
            "region",
            event.x,
            event.y
        )

        if region != "cell":
            return

        column = self.rule_tree.identify_column(
            event.x
        )

        if column != "#1":
            return

        row = self.rule_tree.identify_row(
            event.y
        )

        if not row:
            return

        index = int(row)

        self.rule_entries[index]["enabled"] = not (
            self.rule_entries[index]["enabled"]
        )

        self.filter_rules()

        if str(index) in self.rule_tree.get_children():
            self.rule_tree.selection_set(
                str(index)
            )

            self.rule_tree.focus(
                str(index)
            )

        return "break"

    def enable_all_rules(self):
        for rule in self.rule_entries:
            rule["enabled"] = True

        self.filter_rules()

    def disable_all_rules(self):
        for rule in self.rule_entries:
            rule["enabled"] = False

        self.filter_rules()

    def get_enabled_rules(self):
        return {
            rule["name"]
            for rule in self.rule_entries
            if rule["enabled"]
        }

    def show_rule_details(
        self,
        event=None
    ):
        selected = self.rule_tree.selection()

        if not selected:
            return

        index = int(
            selected[0]
        )

        rule = self.rule_entries[index]

        status = (
            "ENABLED"
            if rule["enabled"]
            else "DISABLED"
        )

        details = [
            f"Rule: {rule['name']}",
            f"Status: {status}",
            "",
            "Source:",
            f"    {rule['source']}",
            ""
        ]

        if rule["tags"]:

            details.append(
                "Tags:"
            )

            for tag in rule["tags"]:

                details.append(
                    f"    {tag}"
                )

            details.append("")

        details.append(
            "Metadata:"
        )

        if rule["meta"]:

            for key, value in rule["meta"].items():

                details.append(
                    f"    {key}: {value}"
                )

        else:

            details.append(
                "    None"
            )

        self.set_rule_details(
            "\n".join(details)
        )

    def set_rule_details(
        self,
        text
    ):
        self.rule_details.config(
            state="normal"
        )

        self.rule_details.delete(
            "1.0",
            "end"
        )

        self.rule_details.insert(
            "1.0",
            text
        )

        self.rule_details.config(
            state="disabled"
        )

    # ======================================================
    # Presets
    # ======================================================

    def load_presets(self):
        self.presets = {}

        if not os.path.isfile(
            self.preset_file
        ):
            return

        try:
            with open(
                self.preset_file,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if isinstance(data, dict):
                self.presets = data

        except Exception:
            self.presets = {}

    def save_presets(self):
        try:
            os.makedirs(
                os.path.dirname(
                    self.preset_file
                ),
                exist_ok=True
            )

            with open(
                self.preset_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.presets,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            return True

        except Exception as error:

            messagebox.showerror(
                "Preset error",
                f"Could not save presets:\n\n{error}"
            )

            return False

    def update_preset_dropdown(self):
        if not hasattr(
            self,
            "preset_combo"
        ):
            return

        names = sorted(
            self.presets.keys(),
            key=str.lower
        )

        self.preset_combo["values"] = [
            ""
        ] + names

        current = self.preset_name.get()

        if current not in names:
            self.preset_name.set("")

    def get_preset_data(
        self,
        name
    ):
        data = self.presets.get(
            name
        )

        if not isinstance(
            data,
            dict
        ):
            return {
                "rules_path": "",
                "rules": {}
            }

        if "rules" in data:
            return {
                "rules_path": data.get(
                    "rules_path",
                    ""
                ),
                "rules": data.get(
                    "rules",
                    {}
                )
            }

        return {
            "rules_path": "",
            "rules": data
        }

    def save_preset(self):
        name = self.preset_name.get().strip()

        if not name:
            from tkinter.simpledialog import askstring

            name = askstring(
                "Save preset",
                "Enter a name for this preset:"
            )

            if not name:
                return

            name = name.strip()

        if not name:
            return

        states = {}

        for rule in self.rule_entries:

            key = (
                f"{rule['source']}::"
                f"{rule['name']}"
            )

            states[key] = bool(
                rule["enabled"]
            )

        self.presets[name] = {
            "rules_path": self.rules_path.get().strip(),
            "rules": states
        }

        if not self.save_presets():
            return

        self.preset_name.set(
            name
        )

        self.update_preset_dropdown()

        self.preset_name.set(
            name
        )

        self.status.config(
            text=f"Preset saved: {name}"
        )

    def load_preset(
        self,
        preset_name=None
    ):
        name = (
            preset_name
            if preset_name is not None
            else self.preset_name.get().strip()
        )

        if not name:
            return

        if name not in self.presets:
            messagebox.showerror(
                "Preset not found",
                f"The preset '{name}' does not exist."
            )

            return

        data = self.get_preset_data(
            name
        )

        saved_path = data.get(
            "rules_path",
            ""
        ).strip()

        current_path = self.rules_path.get().strip()

        if (
            saved_path
            and os.path.normcase(
                os.path.abspath(saved_path)
            )
            != os.path.normcase(
                os.path.abspath(current_path)
            )
        ):

            if os.path.isdir(saved_path):

                switch = messagebox.askyesno(
                    "Switch rules directory?",
                    (
                        f"This preset was saved with a "
                        f"different rules directory:\n\n"
                        f"{saved_path}\n\n"
                        f"Switch to that directory and "
                        f"reload the rules?"
                    )
                )

                if switch:

                    self.rules_path.set(
                        saved_path
                    )

                    self.pending_preset_load = name

                    self.refresh_rules()

                    return

            else:

                apply_current = messagebox.askyesno(
                    "Rules directory unavailable",
                    (
                        f"The rules directory saved with "
                        f"this preset no longer exists:\n\n"
                        f"{saved_path}\n\n"
                        f"Apply the preset to the currently "
                        f"loaded rules instead?"
                    )
                )

                if not apply_current:
                    return

        self.apply_preset(
            name
        )

    def apply_preset(
        self,
        name
    ):
        data = self.get_preset_data(
            name
        )

        states = data.get(
            "rules",
            {}
        )

        if not isinstance(
            states,
            dict
        ):
            states = {}

        matched = 0

        for rule in self.rule_entries:

            key = (
                f"{rule['source']}::"
                f"{rule['name']}"
            )

            if key in states:

                rule["enabled"] = bool(
                    states[key]
                )

                matched += 1

            else:

                rule["enabled"] = True

        self.preset_name.set(
            name
        )

        self.filter_rules()

        self.status.config(
            text=(
                f"Preset loaded: {name} "
                f"({matched} matching rules)"
            )
        )

    def delete_preset(self):
        name = self.preset_name.get().strip()

        if not name:
            return

        if name not in self.presets:
            return

        confirm = messagebox.askyesno(
            "Delete preset",
            f"Delete preset '{name}'?"
        )

        if not confirm:
            return

        del self.presets[name]

        if not self.save_presets():
            return

        self.preset_name.set("")

        self.update_preset_dropdown()

        self.status.config(
            text=f"Preset deleted: {name}"
        )

    def reset_rules(self):
        for rule in self.rule_entries:
            rule["enabled"] = True

        self.preset_name.set("")

        self.filter_rules()

        self.status.config(
            text="All rules enabled"
        )

    # ======================================================
    # Browse
    # ======================================================

    def browse_rules(self):
        path = filedialog.askdirectory(
            title="Select YARA rules directory"
        )

        if path:

            self.rules_path.set(
                path
            )

            self.refresh_rules()

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select file to scan"
        )

        if path:
            self.target_path.set(
                path
            )

    def browse_folder(self):
        path = filedialog.askdirectory(
            title="Select folder to scan"
        )

        if path:
            self.target_path.set(
                path
            )

    # ======================================================
    # Start scan
    # ======================================================

    def start_scan(self):
        rules_path = self.rules_path.get().strip()
        target_path = self.target_path.get().strip()

        if not rules_path:

            messagebox.showerror(
                "Missing rules",
                "Please select a YARA rules directory."
            )

            return

        if not os.path.isdir(rules_path):

            messagebox.showerror(
                "Invalid rules directory",
                "The selected rules directory does not exist."
            )

            return

        if not target_path:

            messagebox.showerror(
                "Missing target",
                "Please select a file or folder to scan."
            )

            return

        if not os.path.exists(target_path):

            messagebox.showerror(
                "Invalid target",
                "The selected target does not exist."
            )

            return

        enabled_rules = self.get_enabled_rules()

        if not enabled_rules:

            messagebox.showwarning(
                "No rules enabled",
                "All YARA rules are currently disabled."
            )

            return

        for item in self.results.get_children():
            self.results.delete(item)

        self.set_details("")

        self.current_results = []
        self.last_scan = None

        self.summary.config(
            text=(
                "Files: 0    "
                "Matches: 0    "
                "Rules triggered: 0    "
                "Failed: 0"
            )
        )

        self.progress.stop()

        self.progress.configure(
            maximum=1,
            value=0,
            style="Horizontal.TProgressbar"
        )

        self.scan_button.config(
            state="disabled"
        )

        self.export_button.config(
            state="disabled"
        )

        self.status.config(
            text=(
                f"Starting scan with "
                f"{len(enabled_rules)} enabled rules..."
            )
        )

        thread = threading.Thread(
            target=self.run_scan,
            args=(
                rules_path,
                target_path,
                enabled_rules
            ),
            daemon=True
        )

        thread.start()

    # ======================================================
    # Background scan
    # ======================================================

    def run_scan(
        self,
        rules_path,
        target_path,
        enabled_rules
    ):
        try:

            rule_files = find_rule_files(
                rules_path
            )

            if not rule_files:

                raise RuntimeError(
                    "No .yar or .yara files were found."
                )

            self.scan_queue.put(
                (
                    "status",
                    f"Compiling {len(rule_files)} rule files..."
                )
            )

            rules, errors = compile_rules(
                rule_files
            )

            if not rules:

                raise RuntimeError(
                    "No YARA rule files could be compiled."
                )

            self.rules = rules

            self.scan_queue.put(
                (
                    "rules_loaded",
                    rules,
                    errors
                )
            )

            self.scan_queue.put(
                (
                    "status",
                    f"Preparing scan with "
                    f"{len(enabled_rules)} enabled rules..."
                )
            )

            def progress_callback(
                current,
                total,
                result
            ):
                self.scan_queue.put(
                    (
                        "progress",
                        current,
                        total,
                        result
                    )
                )

            scan = scan_target(
                target_path,
                rules,
                hash_all=self.hash_all.get(),
                enabled_rules=enabled_rules,
                progress_callback=progress_callback
            )

            self.scan_queue.put(
                (
                    "complete",
                    scan,
                    errors
                )
            )

        except Exception as error:

            self.scan_queue.put(
                (
                    "error",
                    str(error)
                )
            )

    # ======================================================
    # Queue
    # ======================================================

    def process_scan_queue(self):
        try:

            while True:

                message = self.scan_queue.get_nowait()
                message_type = message[0]

                if message_type == "status":

                    self.status.config(
                        text=message[1]
                    )

                elif message_type == "rules_loaded":

                    self.rules = message[1]

                    self.populate_rule_manager()

                    if self.pending_preset_load:
                        preset_name = self.pending_preset_load
                        self.pending_preset_load = None

                        self.apply_preset(
                            preset_name
                        )

                elif message_type == "rules_error":

                    self.status.config(
                        text="Failed to load rules"
                    )

                    messagebox.showerror(
                        "Rule loading error",
                        message[1]
                    )

                elif message_type == "progress":

                    current = message[1]
                    total = message[2]
                    result = message[3]

                    self.progress.stop()

                    self.progress.configure(
                        maximum=max(total, 1),
                        value=current,
                        style="Horizontal.TProgressbar"
                    )

                    self.status.config(
                        text=f"Scanning {current}/{total}"
                    )

                    if result:
                        self.add_result(
                            result
                        )

                elif message_type == "complete":

                    scan = message[1]
                    errors = message[2]

                    self.last_scan = scan

                    self.display_results(
                        scan
                    )

                    self.progress.stop()

                    total = scan["summary"]["files_scanned"]

                    self.progress.configure(
                        maximum=max(total, 1),
                        value=total,
                        style="Green.Horizontal.TProgressbar"
                    )

                    self.scan_button.config(
                        state="normal"
                    )

                    self.export_button.config(
                        state="normal"
                    )

                    if errors:

                        self.status.config(
                            text=(
                                f"Complete "
                                f"({len(errors)} rule files "
                                f"failed to compile)"
                            )
                        )

                    else:

                        self.status.config(
                            text="Scan complete"
                        )

                elif message_type == "error":

                    self.progress.stop()

                    self.scan_button.config(
                        state="normal"
                    )

                    self.export_button.config(
                        state="disabled"
                    )

                    self.status.config(
                        text="Scan failed"
                    )

                    messagebox.showerror(
                        "Scan error",
                        message[1]
                    )

        except queue.Empty:
            pass

        self.after(
            100,
            self.process_scan_queue
        )

    # ======================================================
    # Results
    # ======================================================

    def add_result(
        self,
        result
    ):
        file_path = result["file"]

        if "error" in result:

            status = "FAILED"
            rule_count = "-"
            row_tag = "failed"

        elif result["matched"]:

            status = "MATCH"

            rule_count = len(
                result["rules"]
            )

            row_tag = "match"

        else:

            status = "CLEAN"
            rule_count = 0
            row_tag = "clean"

        if self.results.exists(
            file_path
        ):

            self.results.delete(
                file_path
            )

        self.results.insert(
            "",
            "end",
            iid=file_path,
            values=(
                file_path,
                status,
                rule_count
            ),
            tags=(row_tag,)
        )

    def display_results(
        self,
        scan
    ):
        self.current_results = scan["results"]

        for item in self.results.get_children():

            self.results.delete(
                item
            )

        for result in self.current_results:

            self.add_result(
                result
            )

        summary = scan["summary"]

        self.summary.config(
            text=(
                f"Files: {summary['files_scanned']}    "
                f"Matches: {summary['files_matched']}    "
                f"Rules triggered: "
                f"{summary['rules_triggered']}    "
                f"Failed: {summary['files_failed']}"
            )
        )

    # ======================================================
    # JSON export
    # ======================================================

    def export_json(self):

        if not self.last_scan:

            messagebox.showinfo(
                "Nothing to export",
                "There are no scan results to export."
            )

            return

        path = filedialog.asksaveasfilename(
            title="Export YARA scan results",
            defaultextension=".json",
            initialfile="yara_scan_report.json",
            filetypes=[
                (
                    "JSON files",
                    "*.json"
                ),
                (
                    "All files",
                    "*.*"
                )
            ]
        )

        if not path:
            return

        try:

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.last_scan,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            self.status.config(
                text="JSON report exported"
            )

            messagebox.showinfo(
                "Export complete",
                f"Scan report saved to:\n\n{path}"
            )

        except Exception as error:

            messagebox.showerror(
                "Export failed",
                f"Could not save the report:\n\n{error}"
            )

    # ======================================================
    # Match details
    # ======================================================

    def show_details(
        self,
        event=None
    ):
        selected = self.results.selection()

        if not selected:
            return

        file_path = selected[0]

        result = next(
            (
                result
                for result in self.current_results
                if result["file"] == file_path
            ),
            None
        )

        if not result:
            return

        if "error" in result:

            self.set_details(
                f"File:\n{file_path}\n\n"
                f"ERROR:\n{result['error']}"
            )

            return

        details = []

        details.append(
            f"File: {result['file']}"
        )

        details.append(
            f"Size: {result['size']:,} bytes"
        )

        details.append(
            f"Type: "
            f"{result.get('file_type', 'Unknown')}"
        )

        details.append(
            f"Entropy: "
            f"{result.get('entropy', 0.0):.4f} / 8.0"
        )

        if result["sha256"]:

            details.append(
                f"SHA-256: {result['sha256']}"
            )

        details.append(
            f"Scan time: "
            f"{result['scan_duration_seconds']:.4f} seconds"
        )

        details.append("")

        if not result["matched"]:

            details.append(
                "STATUS: CLEAN"
            )

            details.append(
                "No enabled YARA rules matched this file."
            )

        else:

            details.append(
                "STATUS: MATCH"
            )

            details.append(
                f"Rules triggered: "
                f"{len(result['rules'])}"
            )

            for rule in result["rules"]:

                details.append("")

                details.append(
                    "=" * 70
                )

                details.append(
                    f"Rule: {rule['name']}"
                )

                details.append(
                    f"Source: {rule['source']}"
                )

                if rule["tags"]:

                    details.append(
                        "Tags: "
                        + ", ".join(rule["tags"])
                    )

                if rule["meta"]:

                    details.append(
                        "Metadata:"
                    )

                    for key, value in rule["meta"].items():

                        details.append(
                            f"    {key}: {value}"
                        )

                if rule["strings"]:

                    details.append(
                        "Matched strings:"
                    )

                    for string_match in rule["strings"]:

                        details.append(
                            f"    "
                            f"{string_match['identifier']} "
                            f"@ "
                            f"{string_match['offset']:#x} "
                            f"→ "
                            f"{string_match['data']!r}"
                        )

        self.set_details(
            "\n".join(details)
        )

    def set_details(
        self,
        text
    ):
        self.details.config(
            state="normal"
        )

        self.details.delete(
            "1.0",
            "end"
        )

        self.details.insert(
            "1.0",
            text
        )

        self.details.config(
            state="disabled"
        )


if __name__ == "__main__":
    app = YaraScannerApp()
    app.mainloop()
