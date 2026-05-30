import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import pandas as pd

from .parsers import BrowserParser, run_diagnostics
from .reports import export_json, export_csv, generate_pdf_report

class ForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Browser Forensic Extractor")
        self.root.geometry("1100x700")
        self.root.minsize(950, 600)
        
        # Paths
        self.workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.temp_dir = os.path.join(self.workspace_dir, "temp_extraction")
        
        # State variables
        self.extracted_data = {}
        self.anomalies = []
        self.current_tab = "artifacts"
        self.selected_profile_cat = (None, None) # (profile_name, category)
        
        # Visual Styles - Dark Theme
        self.bg_dark = "#0F172A"       # Deep slate bg
        self.bg_card = "#1E293B"       # Card slate
        self.fg_primary = "#F8FAFC"    # Near white
        self.fg_muted = "#94A3B8"      # Slate gray
        self.accent_blue = "#3B82F6"   # Electric blue
        self.accent_green = "#10B981"  # Emerald green
        self.border_color = "#334155"  # Muted slate border
        self.danger_color = "#EF4444"  # Red
        self.warning_color = "#F59E0B" # Amber
        
        # Configure fonts
        self.font_title = ("Segoe UI", 14, "bold")
        self.font_header = ("Segoe UI", 11, "bold")
        self.font_body = ("Segoe UI", 9)
        self.font_body_bold = ("Segoe UI", 9, "bold")
        self.font_mono = ("Consolas", 9)
        
        # Set theme and apply styling
        self.setup_styles()
        
        # Create Layout
        self.create_widgets()
        
        # Start message
        self.status_label.config(text="Status: Ready. Click 'Scan & Extract' to begin (Forensically Sound - Read-Only).")

    def setup_styles(self):
        self.root.configure(bg=self.bg_dark)
        
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure Treeview (Artifacts and Timeline Grids)
        style.configure("Treeview",
                        background=self.bg_card,
                        foreground=self.fg_primary,
                        fieldbackground=self.bg_card,
                        font=self.font_body,
                        rowheight=25,
                        borderwidth=0)
        style.map("Treeview",
                  background=[("selected", self.accent_blue)],
                  foreground=[("selected", "#FFFFFF")])
        
        style.configure("Treeview.Heading",
                        background="#334155",
                        foreground=self.fg_primary,
                        font=("Segoe UI", 9, "bold"),
                        borderwidth=1,
                        bordercolor=self.border_color)
        
        # Scrollbars styling
        style.configure("Vertical.TScrollbar",
                        background="#334155",
                        troughcolor=self.bg_card,
                        bordercolor=self.border_color,
                        arrowcolor=self.fg_primary)

    def create_widgets(self):
        # 1. TOP HEADER FRAME
        header_frame = tk.Frame(self.root, bg=self.bg_dark, height=70, bd=0, highlightthickness=0)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Title and Subtitle
        title_container = tk.Frame(header_frame, bg=self.bg_dark)
        title_container.pack(side=tk.LEFT, fill=tk.Y)
        
        main_title = tk.Label(title_container, text="BROWSER FORENSIC EXTRACTOR", font=("Segoe UI", 16, "bold"), fg=self.fg_primary, bg=self.bg_dark)
        main_title.pack(anchor=tk.W)
        
        subtitle = tk.Label(title_container, text="Forensic Evidence Acquisition & Analysis (Read-Only Copy Mode)", font=("Segoe UI", 9, "italic"), fg=self.accent_green, bg=self.bg_dark)
        subtitle.pack(anchor=tk.W)
        
        # Action Buttons on Right
        action_container = tk.Frame(header_frame, bg=self.bg_dark)
        action_container.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.scan_button = tk.Button(
            action_container, 
            text="Scan & Extract", 
            font=("Segoe UI", 10, "bold"), 
            bg=self.accent_green, 
            fg="#FFFFFF", 
            activebackground="#059669", 
            activeforeground="#FFFFFF",
            bd=0, 
            padx=15, 
            pady=6, 
            cursor="hand2", 
            command=self.start_extraction_thread
        )
        self.scan_button.pack(side=tk.RIGHT, pady=5)
        
        # Status text in center-right
        self.status_label = tk.Label(action_container, text="Status: Ready", font=self.font_body, fg=self.fg_muted, bg=self.bg_dark, padx=15)
        self.status_label.pack(side=tk.RIGHT, pady=5)

        # Horizontal separator line
        sep = tk.Frame(self.root, bg=self.border_color, height=1)
        sep.pack(fill=tk.X, padx=20)
        
        # 2. CUSTOM NAVBAR TABS
        navbar_frame = tk.Frame(self.root, bg=self.bg_dark, height=40)
        navbar_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.tab_buttons = {}
        tabs = [("artifacts", "Artifacts Explorer"), ("timeline", "Unified Timeline"), ("reports", "Reports & Notes")]
        
        for tab_id, tab_label in tabs:
            btn = tk.Button(
                navbar_frame,
                text=tab_label,
                font=self.font_body_bold,
                bg=self.bg_dark,
                fg=self.fg_muted,
                activebackground=self.bg_dark,
                activeforeground=self.fg_primary,
                bd=0,
                padx=15,
                pady=8,
                cursor="hand2",
                command=lambda tid=tab_id: self.switch_tab(tid)
            )
            btn.pack(side=tk.LEFT)
            btn.bind("<Enter>", lambda e, b=btn: self.on_tab_hover(e, b, True))
            btn.bind("<Leave>", lambda e, b=btn: self.on_tab_hover(e, b, False))
            self.tab_buttons[tab_id] = btn
            
        # Draw active indicator line container
        self.nav_canvas = tk.Canvas(self.root, height=3, bg=self.bg_dark, bd=0, highlightthickness=0)
        self.nav_canvas.pack(fill=tk.X, padx=20)
        self.nav_line = self.nav_canvas.create_line(0, 0, 0, 0, fill=self.accent_blue, width=3)
        
        # Main Work Panel Container
        self.main_content = tk.Frame(self.root, bg=self.bg_dark)
        self.main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Define Sub-Frames for each Tab
        self.artifacts_frame = tk.Frame(self.main_content, bg=self.bg_dark)
        self.timeline_frame = tk.Frame(self.main_content, bg=self.bg_dark)
        self.reports_frame = tk.Frame(self.main_content, bg=self.bg_dark)
        
        # Setup specific views
        self.setup_artifacts_view()
        self.setup_timeline_view()
        self.setup_reports_view()
        
        # Default active tab styling
        self.switch_tab("artifacts")

    def on_tab_hover(self, event, button, is_enter):
        # Don't change styling if it is the currently selected tab
        for tid, btn in self.tab_buttons.items():
            if btn == button:
                if self.current_tab == tid:
                    return
        if is_enter:
            button.config(fg=self.fg_primary)
        else:
            button.config(fg=self.fg_muted)

    def switch_tab(self, tab_id):
        self.current_tab = tab_id
        
        # Hide all frames
        self.artifacts_frame.pack_forget()
        self.timeline_frame.pack_forget()
        self.reports_frame.pack_forget()
        
        # Show selected
        if tab_id == "artifacts":
            self.artifacts_frame.pack(fill=tk.BOTH, expand=True)
        elif tab_id == "timeline":
            self.timeline_frame.pack(fill=tk.BOTH, expand=True)
            self.refresh_timeline_grid()
        elif tab_id == "reports":
            self.reports_frame.pack(fill=tk.BOTH, expand=True)
            self.refresh_reports_tab()
            
        # Update tab button colors
        for tid, btn in self.tab_buttons.items():
            if tid == tab_id:
                btn.config(fg=self.accent_blue)
            else:
                btn.config(fg=self.fg_muted)
                
        # Draw indicator line below active tab
        self.root.update_idletasks() # Ensure dimensions are calculated
        active_btn = self.tab_buttons[tab_id]
        bx = active_btn.winfo_x()
        bw = active_btn.winfo_width()
        self.nav_canvas.coords(self.nav_line, bx, 1, bx + bw, 1)

    # -------------------- TAB 1: ARTIFACTS VIEW --------------------
    def setup_artifacts_view(self):
        # Left Panel: Tree Selector (Browser / Profiles / Categories)
        left_panel = tk.Frame(self.artifacts_frame, bg=self.bg_card, width=250, bd=1, highlightthickness=0)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        left_title = tk.Label(left_panel, text="Browser Profiles", font=self.font_header, fg=self.fg_primary, bg=self.bg_card, pady=10)
        left_title.pack(anchor=tk.W, padx=15)
        
        # Treeview for categories
        self.profile_tree = ttk.Treeview(left_panel, selectmode="browse", show="tree")
        self.profile_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.profile_tree.bind("<<TreeviewSelect>>", self.on_profile_category_select)
        
        # Right Panel: Search Bar, Tree Grid, and Detail Textbox
        right_panel = tk.Frame(self.artifacts_frame, bg=self.bg_dark)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Search & Filter bar
        filter_bar = tk.Frame(right_panel, bg=self.bg_dark)
        filter_bar.pack(fill=tk.X, pady=(0, 10))
        
        search_lbl = tk.Label(filter_bar, text="Search Filter:", font=self.font_body_bold, fg=self.fg_muted, bg=self.bg_dark)
        search_lbl.pack(side=tk.LEFT, padx=(0, 5))
        
        self.artifact_search_var = tk.StringVar()
        self.artifact_search_var.trace_add("write", lambda *args: self.filter_artifacts_grid())
        search_entry = tk.Entry(filter_bar, textvariable=self.artifact_search_var, bg=self.bg_card, fg=self.fg_primary, insertbackground=self.fg_primary, bd=1, relief=tk.FLAT, font=self.font_body, width=40)
        search_entry.pack(side=tk.LEFT, ipady=3)
        
        # Grid Treeview
        grid_container = tk.Frame(right_panel, bg=self.bg_card, bd=1, highlightthickness=0)
        grid_container.pack(fill=tk.BOTH, expand=True)
        
        # We will create a flexible Treeview which dynamically configures columns based on category
        self.artifact_grid = ttk.Treeview(grid_container, selectmode="browse", show="headings")
        self.artifact_grid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.artifact_grid.bind("<<TreeviewSelect>>", self.on_artifact_row_select)
        
        grid_scroll = ttk.Scrollbar(grid_container, orient="vertical", command=self.artifact_grid.yview)
        grid_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.artifact_grid.configure(yscrollcommand=grid_scroll.set)
        
        # Bottom Detail Box
        detail_container = tk.Frame(right_panel, bg=self.bg_card, height=120, bd=1, highlightthickness=0)
        detail_container.pack(fill=tk.X, pady=(10, 0))
        detail_container.pack_propagate(False)
        
        detail_title = tk.Label(detail_container, text="Artifact Details", font=self.font_body_bold, fg=self.accent_blue, bg=self.bg_card)
        detail_title.pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        self.detail_text = tk.Text(detail_container, bg=self.bg_card, fg=self.fg_primary, insertbackground=self.fg_primary, font=self.font_mono, bd=0, wrap=tk.WORD, height=4)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.detail_text.config(state="disabled")

    def populate_profile_tree(self):
        """Populates the left profile-selector tree hierarchical categories."""
        # Clear tree
        for item in self.profile_tree.get_children():
            self.profile_tree.delete(item)
            
        categories = [
            ("history", "History Visits"),
            ("downloads", "Downloads"),
            ("cookies", "Cookies"),
            ("autofill", "Autofill Fields"),
            ("logins", "Saved Logins")
        ]
        
        if not self.extracted_data:
            self.profile_tree.insert("", tk.END, "no_data", text="No profiles extracted")
            return
            
        for profile_name in self.extracted_data.keys():
            # Insert profile parent node
            parent_id = self.profile_tree.insert("", tk.END, text=profile_name, open=True)
            for cat_id, cat_name in categories:
                # Count items
                count = len(self.extracted_data[profile_name].get(cat_id, []))
                node_text = f"{cat_name} ({count})"
                # Node ID is formatted as: profile_name|category
                self.profile_tree.insert(parent_id, tk.END, f"{profile_name}|{cat_id}", text=node_text)

    def on_profile_category_select(self, event):
        selected_items = self.profile_tree.selection()
        if not selected_items:
            return
            
        node_id = selected_items[0]
        if "|" not in node_id:
            # Clicked a parent node (profile name), skip loading
            return
            
        profile_name, category = node_id.split("|")
        self.selected_profile_cat = (profile_name, category)
        self.artifact_search_var.set("") # Clear search
        self.load_artifacts_category(profile_name, category)

    def load_artifacts_category(self, profile_name, category):
        """Draws correct headers and inserts rows into the Artifact Grid for a selected category."""
        # Clear grid
        self.artifact_grid.delete(*self.artifact_grid.get_children())
        
        data_list = self.extracted_data.get(profile_name, {}).get(category, [])
        
        # Define Columns based on category
        cols_config = {
            'history': [
                ("Timestamp", 160), ("URL", 300), ("Title", 250), 
                ("Duration (s)", 90), ("Visit Count", 80), ("Typed Count", 80)
            ],
            'downloads': [
                ("Timestamp", 160), ("File Name", 180), ("State", 90), 
                ("Total Bytes", 90), ("Target Path", 300), ("Download Referrer", 300)
            ],
            'cookies': [
                ("Timestamp", 160), ("Host / Domain", 200), ("Name", 120), 
                ("Value (Decrypted)", 220), ("Expiry", 160), ("Secure", 60), ("HttpOnly", 60)
            ],
            'autofill': [
                ("Timestamp", 160), ("Field Name", 180), ("Value", 220), ("Usage Count", 90)
            ],
            'logins': [
                ("Timestamp", 160), ("Origin Domain", 220), ("Username Element", 140), 
                ("Username Value", 160), ("Password Element", 140), ("Password (Decrypted)", 160)
            ]
        }
        
        config = cols_config.get(category, [])
        col_names = [col[0] for col in config]
        
        self.artifact_grid.config(columns=col_names)
        
        for col_name, width in config:
            self.artifact_grid.heading(col_name, text=col_name, anchor=tk.W)
            self.artifact_grid.column(col_name, width=width, anchor=tk.W)
            
        # Save active data list for searching
        self.current_grid_data = data_list
        self.filter_artifacts_grid()

    def filter_artifacts_grid(self):
        """Filters the current grid data based on search text."""
        if not hasattr(self, 'current_grid_data') or not self.selected_profile_cat[0]:
            return
            
        # Clear grid rows
        self.artifact_grid.delete(*self.artifact_grid.get_children())
        
        search_query = self.artifact_search_var.get().lower().strip()
        category = self.selected_profile_cat[1]
        
        for item in self.current_grid_data:
            # Map item fields to grid row values
            row_vals = []
            if category == 'history':
                row_vals = [item['timestamp'], item['url'], item['title'], item['visit_duration'], item['visit_count'], item['typed_count']]
            elif category == 'downloads':
                row_vals = [item['timestamp'], item['file_name'], item['state'], item['total_bytes'], item['target_path'], item['referrer']]
            elif category == 'cookies':
                row_vals = [item['timestamp'], item['host'], item['name'], item['value'], item['expiry'], item['is_secure'], item['is_httponly']]
            elif category == 'autofill':
                row_vals = [item['timestamp'], item['field_name'], item['value'], item['count']]
            elif category == 'logins':
                row_vals = [item['timestamp'], item['origin_url'], item['username_element'], item['username_value'], item['password_element'], item['password_value']]
                
            # Perform search check
            if search_query:
                match = False
                for val in row_vals:
                    if val is not None and search_query in str(val).lower():
                        match = True
                        break
                if not match:
                    continue
                    
            self.artifact_grid.insert("", tk.END, values=row_vals)

    def on_artifact_row_select(self, event):
        """Displays detail of selected row in the bottom detail panel."""
        selected = self.artifact_grid.selection()
        if not selected:
            return
            
        row_vals = self.artifact_grid.item(selected[0], "values")
        category = self.selected_profile_cat[1]
        
        # Build formatted details text based on selected values
        detail_lines = []
        if category == 'history':
            detail_lines = [
                f"TIMESTAMP: {row_vals[0]}",
                f"URL:       {row_vals[1]}",
                f"TITLE:     {row_vals[2]}",
                f"DURATION:  {row_vals[3]} seconds",
                f"VISIT CNT: {row_vals[4]} | TYPED CNT: {row_vals[5]}"
            ]
        elif category == 'downloads':
            detail_lines = [
                f"TIMESTAMP: {row_vals[0]}",
                f"FILE NAME: {row_vals[1]}",
                f"STATUS:    {row_vals[2]}",
                f"FILE SIZE: {row_vals[3]} bytes",
                f"LOCAL PATH:{row_vals[4]}",
                f"REFERRER:  {row_vals[5]}"
            ]
        elif category == 'cookies':
            detail_lines = [
                f"TIMESTAMP: {row_vals[0]}",
                f"DOMAIN:    {row_vals[1]}",
                f"COOKIE NM: {row_vals[2]}",
                f"VALUE:     {row_vals[3]}",
                f"EXPIRY:    {row_vals[4]}",
                f"SECURE:    {row_vals[5]} | HTTPONLY: {row_vals[6]}"
            ]
        elif category == 'autofill':
            detail_lines = [
                f"TIMESTAMP:  {row_vals[0]}",
                f"FIELD NAME: {row_vals[1]}",
                f"VALUE:      {row_vals[2]}",
                f"USAGE CNT:  {row_vals[3]}"
            ]
        elif category == 'logins':
            detail_lines = [
                f"TIMESTAMP:   {row_vals[0]}",
                f"ORIGIN URL:  {row_vals[1]}",
                f"USER ELM:    {row_vals[2]}",
                f"USER VALUE:  {row_vals[3]}",
                f"PASS ELM:    {row_vals[4]}",
                f"DECRYPTED P: {row_vals[5]}"
            ]
            
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", "\n".join(detail_lines))
        self.detail_text.config(state="disabled")

    # -------------------- TAB 2: UNIFIED TIMELINE VIEW --------------------
    def setup_timeline_view(self):
        # Filters Header Panel
        filter_panel = tk.Frame(self.timeline_frame, bg=self.bg_card, bd=1, highlightthickness=0)
        filter_panel.pack(fill=tk.X, pady=(0, 10))
        
        # Grid cells layout for filters
        tk.Label(filter_panel, text="Date Filters (YYYY-MM-DD)", font=self.font_body_bold, fg=self.fg_primary, bg=self.bg_card).grid(row=0, column=0, columnspan=2, padx=10, pady=(5, 0), sticky=tk.W)
        
        tk.Label(filter_panel, text="Start Date:", font=self.font_body, fg=self.fg_muted, bg=self.bg_card).grid(row=1, column=0, padx=(10, 5), pady=5, sticky=tk.W)
        self.timeline_start_var = tk.StringVar()
        self.timeline_start_var.trace_add("write", lambda *args: self.refresh_timeline_grid())
        start_entry = tk.Entry(filter_panel, textvariable=self.timeline_start_var, width=12, bg=self.bg_dark, fg=self.fg_primary, bd=0, insertbackground=self.fg_primary, font=self.font_body)
        start_entry.grid(row=1, column=1, padx=(0, 15), pady=5)
        
        tk.Label(filter_panel, text="End Date:", font=self.font_body, fg=self.fg_muted, bg=self.bg_card).grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.timeline_end_var = tk.StringVar()
        self.timeline_end_var.trace_add("write", lambda *args: self.refresh_timeline_grid())
        end_entry = tk.Entry(filter_panel, textvariable=self.timeline_end_var, width=12, bg=self.bg_dark, fg=self.fg_primary, bd=0, insertbackground=self.fg_primary, font=self.font_body)
        end_entry.grid(row=1, column=3, padx=(0, 15), pady=5)
        
        # Text Search
        tk.Label(filter_panel, text="Text Filter:", font=self.font_body_bold, fg=self.fg_primary, bg=self.bg_card).grid(row=1, column=4, padx=(10, 5), pady=5, sticky=tk.W)
        self.timeline_search_var = tk.StringVar()
        self.timeline_search_var.trace_add("write", lambda *args: self.refresh_timeline_grid())
        search_entry = tk.Entry(filter_panel, textvariable=self.timeline_search_var, width=25, bg=self.bg_dark, fg=self.fg_primary, bd=0, insertbackground=self.fg_primary, font=self.font_body)
        search_entry.grid(row=1, column=5, padx=(0, 20), pady=5)
        
        # Checkboxes for categories
        checkboxes_frame = tk.Frame(filter_panel, bg=self.bg_card)
        checkboxes_frame.grid(row=0, column=6, rowspan=2, padx=10, pady=5, sticky=tk.W)
        
        self.timeline_filters = {
            'History': tk.BooleanVar(value=True),
            'Download': tk.BooleanVar(value=True),
            'Cookie': tk.BooleanVar(value=True),
            'Autofill': tk.BooleanVar(value=True),
            'Login': tk.BooleanVar(value=True)
        }
        
        col_idx = 0
        for name, var in self.timeline_filters.items():
            cb = tk.Checkbutton(
                checkboxes_frame, 
                text=name, 
                variable=var, 
                bg=self.bg_card, 
                fg=self.fg_primary,
                selectcolor=self.bg_card, 
                activebackground=self.bg_card, 
                activeforeground=self.fg_primary,
                font=self.font_body, 
                command=self.refresh_timeline_grid
            )
            cb.grid(row=0, column=col_idx, padx=8)
            col_idx += 1
            
        # Timeline Treeview Grid
        grid_container = tk.Frame(self.timeline_frame, bg=self.bg_card, bd=1, highlightthickness=0)
        grid_container.pack(fill=tk.BOTH, expand=True)
        
        cols = ("Timestamp (UTC)", "Browser Source", "Table Source", "Event Type", "Primary Description", "Secondary Details")
        self.timeline_grid = ttk.Treeview(grid_container, columns=cols, selectmode="browse", show="headings")
        self.timeline_grid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.timeline_grid.bind("<<TreeviewSelect>>", self.on_timeline_row_select)
        
        grid_scroll = ttk.Scrollbar(grid_container, orient="vertical", command=self.timeline_grid.yview)
        grid_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.timeline_grid.configure(yscrollcommand=grid_scroll.set)
        
        # Column dimensions
        self.timeline_grid.heading(cols[0], text=cols[0], anchor=tk.W)
        self.timeline_grid.column(cols[0], width=160, anchor=tk.W)
        self.timeline_grid.heading(cols[1], text=cols[1], anchor=tk.W)
        self.timeline_grid.column(cols[1], width=130, anchor=tk.W)
        self.timeline_grid.heading(cols[2], text=cols[2], anchor=tk.W)
        self.timeline_grid.column(cols[2], width=85, anchor=tk.W)
        self.timeline_grid.heading(cols[3], text=cols[3], anchor=tk.W)
        self.timeline_grid.column(cols[3], width=110, anchor=tk.W)
        self.timeline_grid.heading(cols[4], text=cols[4], anchor=tk.W)
        self.timeline_grid.column(cols[4], width=260, anchor=tk.W)
        self.timeline_grid.heading(cols[5], text=cols[5], anchor=tk.W)
        self.timeline_grid.column(cols[5], width=260, anchor=tk.W)

        # Bottom Detail Box
        detail_container = tk.Frame(self.timeline_frame, bg=self.bg_card, height=100, bd=1, highlightthickness=0)
        detail_container.pack(fill=tk.X, pady=(10, 0))
        detail_container.pack_propagate(False)
        
        detail_title = tk.Label(detail_container, text="Event Details", font=self.font_body_bold, fg=self.accent_blue, bg=self.bg_card)
        detail_title.pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        self.timeline_detail_text = tk.Text(detail_container, bg=self.bg_card, fg=self.fg_primary, insertbackground=self.fg_primary, font=self.font_mono, bd=0, wrap=tk.WORD, height=3)
        self.timeline_detail_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.timeline_detail_text.config(state="disabled")

    def build_unified_timeline_df(self) -> pd.DataFrame:
        """Consolidates all history, download, cookies, autofill, and login records to a single sorted DataFrame."""
        records = []
        if not self.extracted_data:
            return pd.DataFrame(columns=['timestamp', 'browser', 'source_table', 'event_type', 'primary_info', 'secondary_info'])
            
        for profile, data in self.extracted_data.items():
            # History
            for h in data.get('history', []):
                records.append({
                    'timestamp': h['timestamp'],
                    'browser': h['browser'],
                    'source_table': h['source'],
                    'event_type': 'Page Visit',
                    'primary_info': h['url'],
                    'secondary_info': h['title']
                })
            # Downloads
            for dl in data.get('downloads', []):
                records.append({
                    'timestamp': dl['timestamp'],
                    'browser': dl['browser'],
                    'source_table': dl['source'],
                    'event_type': f"Download ({dl['state']})",
                    'primary_info': dl['file_name'],
                    'secondary_info': dl['target_path']
                })
            # Cookies
            for c in data.get('cookies', []):
                records.append({
                    'timestamp': c['timestamp'],
                    'browser': c['browser'],
                    'source_table': c['source'],
                    'event_type': 'Cookie Creation',
                    'primary_info': c['host'],
                    'secondary_info': f"Name: {c['name']}"
                })
            # Autofill
            for af in data.get('autofill', []):
                records.append({
                    'timestamp': af['timestamp'],
                    'browser': af['browser'],
                    'source_table': af['source'],
                    'event_type': 'Autofill Entry',
                    'primary_info': af['field_name'],
                    'secondary_info': af['value']
                })
            # Logins
            for l in data.get('logins', []):
                records.append({
                    'timestamp': l['timestamp'],
                    'browser': l['browser'],
                    'source_table': l['source'],
                    'event_type': 'Login Attempt',
                    'primary_info': l['origin_url'],
                    'secondary_info': f"Username Field: {l['username_element']}, Value: {l['username_value']}"
                })
                
        df = pd.DataFrame(records)
        df['dt_parsed'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.sort_values(by='dt_parsed', ascending=False)
        return df

    def refresh_timeline_grid(self):
        """Refreshes the timeline grid rows based on dates, search filters, and active tab."""
        if self.current_tab != "timeline":
            return
            
        self.timeline_grid.delete(*self.timeline_grid.get_children())
        
        df = self.build_unified_timeline_df()
        if df.empty:
            return
            
        # Apply Category Filters
        active_cats = [name for name, var in self.timeline_filters.items() if var.get()]
        df = df[df['source_table'].isin(active_cats)]
        
        # Apply Start Date Filter
        start_date_str = self.timeline_start_var.get().strip()
        if start_date_str:
            try:
                start_dt = pd.to_datetime(start_date_str)
                df = df[df['dt_parsed'] >= start_dt]
            except Exception:
                pass # Silent ignore invalid date format
                
        # Apply End Date Filter
        end_date_str = self.timeline_end_var.get().strip()
        if end_date_str:
            try:
                # Add 1 day to end date to make filter inclusive of the end day
                end_dt = pd.to_datetime(end_date_str) + pd.Timedelta(days=1)
                df = df[df['dt_parsed'] <= end_dt]
            except Exception:
                pass
                
        # Apply Text Search Filter
        search_query = self.timeline_search_var.get().lower().strip()
        if search_query:
            # Match search in primary_info or secondary_info or event_type
            df = df[
                df['primary_info'].str.lower().str.contains(search_query, na=False) |
                df['secondary_info'].str.lower().str.contains(search_query, na=False) |
                df['event_type'].str.lower().str.contains(search_query, na=False)
            ]
            
        # Load up to 10,000 items (safety cap for GUI speed)
        df_limited = df.head(10000)
        for _, row in df_limited.iterrows():
            row_vals = [
                row['timestamp'], 
                row['browser'], 
                row['source_table'], 
                row['event_type'], 
                row['primary_info'], 
                row['secondary_info']
            ]
            self.timeline_grid.insert("", tk.END, values=row_vals)

    def on_timeline_row_select(self, event):
        selected = self.timeline_grid.selection()
        if not selected:
            return
        row_vals = self.timeline_grid.item(selected[0], "values")
        
        detail_lines = [
            f"TIMESTAMP:    {row_vals[0]}",
            f"BROWSER:      {row_vals[1]}",
            f"SOURCE TABLE: {row_vals[2]}",
            f"EVENT TYPE:   {row_vals[3]}",
            f"PRIMARY DESC: {row_vals[4]}",
            f"SECONDARY:    {row_vals[5]}"
        ]
        
        self.timeline_detail_text.config(state="normal")
        self.timeline_detail_text.delete("1.0", tk.END)
        self.timeline_detail_text.insert("1.0", "\n".join(detail_lines))
        self.timeline_detail_text.config(state="disabled")

    # -------------------- TAB 3: REPORTS & SETTINGS VIEW --------------------
    def setup_reports_view(self):
        # Split into Left Panel (Case Metadata Forms) and Right Panel (Diagnostic Flags Dashboard)
        left_panel = tk.Frame(self.reports_frame, bg=self.bg_card, width=420, bd=1, highlightthickness=0)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        left_title = tk.Label(left_panel, text="Case Details & Notes", font=self.font_header, fg=self.fg_primary, bg=self.bg_card, pady=10)
        left_title.pack(anchor=tk.W, padx=15)
        
        form_frame = tk.Frame(left_panel, bg=self.bg_card)
        form_frame.pack(fill=tk.X, padx=15)
        
        # Form inputs
        tk.Label(form_frame, text="Case ID:", font=self.font_body_bold, fg=self.fg_muted, bg=self.bg_card).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.case_id_var = tk.StringVar(value="INV-2026-001")
        case_entry = tk.Entry(form_frame, textvariable=self.case_id_var, font=self.font_body, bg=self.bg_dark, fg=self.fg_primary, bd=0, width=30)
        case_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(form_frame, text="Suspect Name:", font=self.font_body_bold, fg=self.fg_muted, bg=self.bg_card).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.suspect_var = tk.StringVar(value="John Doe")
        suspect_entry = tk.Entry(form_frame, textvariable=self.suspect_var, font=self.font_body, bg=self.bg_dark, fg=self.fg_primary, bd=0, width=30)
        suspect_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(form_frame, text="Device Name:", font=self.font_body_bold, fg=self.fg_muted, bg=self.bg_card).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.device_var = tk.StringVar(value="SUSPECT-PC-WIN")
        device_entry = tk.Entry(form_frame, textvariable=self.device_var, font=self.font_body, bg=self.bg_dark, fg=self.fg_primary, bd=0, width=30)
        device_entry.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(form_frame, text="Investigator:", font=self.font_body_bold, fg=self.fg_muted, bg=self.bg_card).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.investigator_var = tk.StringVar(value="Agent Shreya")
        inv_entry = tk.Entry(form_frame, textvariable=self.investigator_var, font=self.font_body, bg=self.bg_dark, fg=self.fg_primary, bd=0, width=30)
        inv_entry.grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Investigator Notes
        tk.Label(left_panel, text="Forensic Investigation Narrative / Notes:", font=self.font_body_bold, fg=self.fg_primary, bg=self.bg_card).pack(anchor=tk.W, padx=15, pady=(15, 5))
        self.notes_text = tk.Text(left_panel, bg=self.bg_dark, fg=self.fg_primary, insertbackground=self.fg_primary, font=self.font_body, bd=0, height=12)
        self.notes_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
        self.notes_text.insert("1.0", "The system analysis was conducted inside a forensically isolated sandbox environment. Browser files were acquired in read-only copy mode. Decryption keys were fetched using ctypes DPAPI calls to local state profiles.")
        
        # Export Buttons container
        buttons_frame = tk.Frame(left_panel, bg=self.bg_card)
        buttons_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # JSON export
        btn_json = tk.Button(buttons_frame, text="Export JSON Report", font=self.font_body_bold, bg=self.accent_blue, fg="#FFFFFF", bd=0, padx=10, pady=8, cursor="hand2", command=self.action_export_json)
        btn_json.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        # CSV export
        btn_csv = tk.Button(buttons_frame, text="Export CSV Timeline", font=self.font_body_bold, bg=self.accent_blue, fg="#FFFFFF", bd=0, padx=10, pady=8, cursor="hand2", command=self.action_export_csv)
        btn_csv.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # PDF report
        btn_pdf = tk.Button(buttons_frame, text="Generate PDF Report", font=self.font_body_bold, bg=self.accent_green, fg="#FFFFFF", bd=0, padx=10, pady=8, cursor="hand2", command=self.action_export_pdf)
        btn_pdf.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        # Right Panel: Diagnostics Board
        right_panel = tk.Frame(self.reports_frame, bg=self.bg_card, bd=1, highlightthickness=0)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_title = tk.Label(right_panel, text="Forensic Findings & Diagnostic Flags", font=self.font_header, fg=self.fg_primary, bg=self.bg_card, pady=10)
        right_title.pack(anchor=tk.W, padx=15)
        
        # Grid containing findings
        self.findings_grid = ttk.Treeview(right_panel, columns=("Severity", "Category", "Description"), show="headings", selectmode="none")
        self.findings_grid.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        self.findings_grid.heading("Severity", text="Severity", anchor=tk.W)
        self.findings_grid.column("Severity", width=80, anchor=tk.W)
        self.findings_grid.heading("Category", text="Category", anchor=tk.W)
        self.findings_grid.column("Category", width=120, anchor=tk.W)
        self.findings_grid.heading("Description", text="Diagnostic Analysis / Finding Description", anchor=tk.W)
        self.findings_grid.column("Description", width=360, anchor=tk.W)

    def refresh_reports_tab(self):
        """Updates the Diagnostic Flags Treeview with anomalies list."""
        self.findings_grid.delete(*self.findings_grid.get_children())
        
        if not self.anomalies:
            self.findings_grid.insert("", tk.END, values=("INFO", "Diagnostics Check", "No critical anomalies or suspicious history deletions flagged yet. Run 'Scan & Extract' first."))
            return
            
        for anom in self.anomalies:
            self.findings_grid.insert("", tk.END, values=(anom['severity'], anom['category'], anom['message']))

    # -------------------- EXTRACTION THREAD LOGIC --------------------
    def start_extraction_thread(self):
        # Guard clause
        if hasattr(self, 'extract_thread') and self.extract_thread.is_alive():
            messagebox.showwarning("In Progress", "An extraction scan is already active in the background.")
            return
            
        self.scan_button.config(state="disabled", bg="#475569")
        self.status_label.config(text="Status: Scanning system and acquiring browser databases (Read-Only Copy Mode)...", fg=self.accent_blue)
        
        self.extract_thread = threading.Thread(target=self.run_extraction_task, daemon=True)
        self.extract_thread.start()

    def run_extraction_task(self):
        try:
            # 1. Instantiate the parser with a workspace-localized temp_extraction directory
            parser = BrowserParser(self.temp_dir)
            
            # 2. Extract Data
            data = parser.run_extraction()
            
            # 3. Run Analysis & Heuristics Diagnostics
            anomalies = run_diagnostics(data)
            
            # 4. Success callback to GUI thread
            self.root.after(0, lambda: self.on_extraction_success(data, anomalies))
        except Exception as e:
            # Failure callback
            import traceback
            traceback.print_exc()
            self.root.after(0, lambda err=str(e): self.on_extraction_failure(err))

    def on_extraction_success(self, data, anomalies):
        self.extracted_data = data
        self.anomalies = anomalies
        
        self.scan_button.config(state="normal", bg=self.accent_green)
        self.status_label.config(text=f"Status: Extraction Successful! Loaded {len(data)} profile(s). Findings Flagged: {len(anomalies)}", fg=self.accent_green)
        
        # Repopulate selectors and timeline
        self.populate_profile_tree()
        self.refresh_timeline_grid()
        self.refresh_reports_tab()
        
        # Switch select context
        messagebox.showinfo("Extraction Complete", f"Data acquisition successfully completed.\nProfile(s) found: {len(data)}\nDiagnostic flags: {len(anomalies)}\nOriginal files remain untouched.")

    def on_extraction_failure(self, err_msg):
        self.scan_button.config(state="normal", bg=self.accent_green)
        self.status_label.config(text="Status: Scan failed", fg=self.danger_color)
        messagebox.showerror("Extraction Error", f"An error occurred while copying or parsing database files:\n{err_msg}")

    # -------------------- REPORT EXPORT HANDLERS --------------------
    def get_case_metadata(self) -> dict:
        return {
            "case_id": self.case_id_var.get().strip() or "N/A",
            "suspect_name": self.suspect_var.get().strip() or "N/A",
            "device_name": self.device_var.get().strip() or "N/A",
            "investigator": self.investigator_var.get().strip() or "N/A",
            "notes": self.notes_text.get("1.0", tk.END).strip()
        }

    def action_export_json(self):
        if not self.extracted_data:
            messagebox.showwarning("No Data", "No extraction data exists. Run 'Scan & Extract' first.")
            return
            
        case_meta = self.get_case_metadata()
        default_name = f"Case_{case_meta['case_id']}_Forensic_Report.json"
        
        filepath = filedialog.asksaveasfilename(
            initialdir=self.workspace_dir,
            initialfile=default_name,
            title="Save JSON Forensic Report",
            filetypes=(("JSON Files", "*.json"), ("All Files", "*.*"))
        )
        
        if filepath:
            try:
                export_json(self.extracted_data, self.anomalies, case_meta, filepath)
                messagebox.showinfo("Export Successful", f"Case data exported successfully to:\n{os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save JSON report:\n{e}")

    def action_export_csv(self):
        if not self.extracted_data:
            messagebox.showwarning("No Data", "No extraction data exists. Run 'Scan & Extract' first.")
            return
            
        case_meta = self.get_case_metadata()
        default_name = f"Case_{case_meta['case_id']}_Timeline_Report.csv"
        
        filepath = filedialog.asksaveasfilename(
            initialdir=self.workspace_dir,
            initialfile=default_name,
            title="Save CSV Unified Timeline",
            filetypes=(("CSV Files", "*.csv"), ("All Files", "*.*"))
        )
        
        if filepath:
            try:
                export_csv(self.extracted_data, filepath)
                messagebox.showinfo("Export Successful", f"Unified timeline exported successfully to:\n{os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save CSV timeline:\n{e}")

    def action_export_pdf(self):
        if not self.extracted_data:
            messagebox.showwarning("No Data", "No extraction data exists. Run 'Scan & Extract' first.")
            return
            
        # Ensure reportlab is loaded
        try:
            import reportlab
        except ImportError:
            messagebox.showerror("Missing Dependency", "The 'reportlab' package is required for PDF exports. Verify that the dependency installation task has completed.")
            return
            
        case_meta = self.get_case_metadata()
        default_name = f"Case_{case_meta['case_id']}_Forensic_Report.pdf"
        
        filepath = filedialog.asksaveasfilename(
            initialdir=self.workspace_dir,
            initialfile=default_name,
            title="Save PDF Case Report",
            filetypes=(("PDF Files", "*.pdf"), ("All Files", "*.*"))
        )
        
        if filepath:
            try:
                generate_pdf_report(self.extracted_data, self.anomalies, case_meta, filepath)
                messagebox.showinfo("Export Successful", f"PDF Report generated successfully to:\n{os.path.basename(filepath)}")
            except Exception as e:
                import traceback
                traceback.print_exc()
                messagebox.showerror("Export Error", f"Failed to generate PDF Report:\n{e}")

    def clean_temp_files(self):
        """Cleans extracted SQLite databases from the workspace temp_extraction directory."""
        if os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
                print("Cleaned temporary forensic file copies.")
            except Exception as e:
                print(f"Error cleaning temp directory: {e}")
