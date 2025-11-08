#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import sqlite3
import time
import threading
from contextlib import closing
from tkinter import filedialog
import customtkinter as ctk
from typing import Optional

# Import core functions from ulptool
from ulptool import (
    APP_NAME, BRAND, OUTPUT_PREFIX, DB_NAME, BATCH_SIZE,
    APP_DIR, DOMAINS_JSON, DDL, UPSERT_SQL, SELECT_SUMMARY, SELECT_DOMAIN_ROWS,
    effective_domain, parse_line, is_email, is_phone_like, is_numeric_id,
    load_saved_domains, save_domains, ensure_app_dir
)

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ULPToolGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window configuration
        self.title(f"{APP_NAME} - Modern UI")
        self.geometry("900x700")
        self.minsize(800, 600)

        # Color scheme (Apple-inspired dark theme)
        self.colors = {
            "bg_primary": "#1c1c1e",
            "bg_secondary": "#2c2c2e",
            "bg_tertiary": "#3a3a3c",
            "accent": "#0a84ff",
            "accent_hover": "#409cff",
            "success": "#32d74b",
            "warning": "#ff9f0a",
            "danger": "#ff453a",
            "text_primary": "#ffffff",
            "text_secondary": "#98989d"
        }

        # State variables
        self.selected_file: Optional[str] = None
        self.sorting_mode = ctk.StringVar(value="email")
        self.domains_to_use = []
        self.processing = False

        # Build UI
        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI layout"""
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        self.create_header()

        # Main content area with scrollable frame
        self.main_container = ctk.CTkScrollableFrame(
            self,
            fg_color=self.colors["bg_primary"],
            corner_radius=0
        )
        self.main_container.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Setup wizard-style interface
        self.create_file_selection()
        self.create_sorting_mode_selection()
        self.create_domain_management()
        self.create_action_buttons()
        self.create_results_area()

        # Footer
        self.create_footer()

    def create_header(self):
        """Create the application header"""
        header = ctk.CTkFrame(self, fg_color=self.colors["bg_secondary"], corner_radius=0, height=80)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(0, weight=1)
        header.grid_propagate(False)

        # App title with icon
        title_label = ctk.CTkLabel(
            header,
            text=f"⚡ {APP_NAME}",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=self.colors["accent"]
        )
        title_label.grid(row=0, column=0, pady=(15, 0))

        # Subtitle
        subtitle_label = ctk.CTkLabel(
            header,
            text="PSL-aware • Huge-file streaming • Disk dedupe",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        )
        subtitle_label.grid(row=1, column=0, pady=(0, 15))

    def create_file_selection(self):
        """Create file selection section"""
        section = ctk.CTkFrame(self.main_container, fg_color=self.colors["bg_secondary"], corner_radius=12)
        section.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        section.grid_columnconfigure(0, weight=1)

        # Section title
        title = ctk.CTkLabel(
            section,
            text="📁 Select Input File",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        title.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))

        # File info label
        self.file_label = ctk.CTkLabel(
            section,
            text="No file selected",
            font=ctk.CTkFont(size=13),
            text_color=self.colors["text_secondary"],
            anchor="w"
        )
        self.file_label.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))

        # Browse button
        browse_btn = ctk.CTkButton(
            section,
            text="Browse Files",
            command=self.browse_file,
            fg_color=self.colors["accent"],
            hover_color=self.colors["accent_hover"],
            corner_radius=8,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        browse_btn.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))

    def create_sorting_mode_selection(self):
        """Create sorting mode selection section"""
        section = ctk.CTkFrame(self.main_container, fg_color=self.colors["bg_secondary"], corner_radius=12)
        section.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        section.grid_columnconfigure(0, weight=1)

        # Section title
        title = ctk.CTkLabel(
            section,
            text="🔍 Sorting Mode",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        title.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))

        # Radio buttons
        modes = [
            ("email", "Email:Pass - Only email addresses"),
            ("number", "Phone/Number:Pass - Phone numbers and IDs"),
            ("all", "All - Email, phone, and numeric IDs"),
            ("any", "Any:Pass - All usernames (no filtering)")
        ]

        for idx, (value, label) in enumerate(modes):
            radio = ctk.CTkRadioButton(
                section,
                text=label,
                variable=self.sorting_mode,
                value=value,
                font=ctk.CTkFont(size=13),
                fg_color=self.colors["accent"],
                hover_color=self.colors["accent_hover"],
                border_color=self.colors["text_secondary"]
            )
            radio.grid(row=idx+1, column=0, sticky="w", padx=40, pady=5)

        # Add spacing at bottom
        ctk.CTkLabel(section, text="", height=10).grid(row=len(modes)+1, column=0)

    def create_domain_management(self):
        """Create domain management section"""
        section = ctk.CTkFrame(self.main_container, fg_color=self.colors["bg_secondary"], corner_radius=12)
        section.grid(row=2, column=0, sticky="ew", padx=20, pady=10)
        section.grid_columnconfigure(0, weight=1)

        # Section title
        title = ctk.CTkLabel(
            section,
            text="🌐 Domain Management",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        title.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))

        # Instruction
        instruction = ctk.CTkLabel(
            section,
            text="Enter domains separated by commas (e.g., capcut.com, dropbox.com, facebook.com)",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"],
            anchor="w"
        )
        instruction.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))

        # Domain input textbox
        self.domain_input = ctk.CTkTextbox(
            section,
            height=100,
            corner_radius=8,
            font=ctk.CTkFont(size=13),
            fg_color=self.colors["bg_tertiary"],
            border_color=self.colors["text_secondary"],
            border_width=1
        )
        self.domain_input.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))

        # Load saved domains if available
        saved = load_saved_domains()
        if saved:
            self.domain_input.insert("1.0", ", ".join(saved))

        # Buttons frame
        btn_frame = ctk.CTkFrame(section, fg_color="transparent")
        btn_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 15))
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        # Load saved button
        load_btn = ctk.CTkButton(
            btn_frame,
            text="Load Saved",
            command=self.load_saved_domains,
            fg_color=self.colors["bg_tertiary"],
            hover_color=self.colors["accent"],
            corner_radius=8,
            height=35,
            font=ctk.CTkFont(size=13)
        )
        load_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        # Save button
        save_btn = ctk.CTkButton(
            btn_frame,
            text="Save Domains",
            command=self.save_domains_list,
            fg_color=self.colors["success"],
            hover_color="#28a745",
            corner_radius=8,
            height=35,
            font=ctk.CTkFont(size=13)
        )
        save_btn.grid(row=0, column=1, sticky="ew", padx=(5, 0))

    def create_action_buttons(self):
        """Create main action buttons"""
        section = ctk.CTkFrame(self.main_container, fg_color="transparent")
        section.grid(row=3, column=0, sticky="ew", padx=20, pady=20)
        section.grid_columnconfigure(0, weight=1)

        # Start processing button
        self.start_btn = ctk.CTkButton(
            section,
            text="▶ Start Processing",
            command=self.start_processing,
            fg_color=self.colors["accent"],
            hover_color=self.colors["accent_hover"],
            corner_radius=10,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.start_btn.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        # Progress bar
        self.progress = ctk.CTkProgressBar(
            section,
            corner_radius=8,
            height=20,
            progress_color=self.colors["success"],
            fg_color=self.colors["bg_tertiary"]
        )
        self.progress.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        self.progress.set(0)

        # Progress label
        self.progress_label = ctk.CTkLabel(
            section,
            text="Ready to process",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"]
        )
        self.progress_label.grid(row=2, column=0, sticky="w")

    def create_results_area(self):
        """Create results display area"""
        self.results_section = ctk.CTkFrame(
            self.main_container,
            fg_color=self.colors["bg_secondary"],
            corner_radius=12
        )
        self.results_section.grid(row=4, column=0, sticky="ew", padx=20, pady=(10, 20))
        self.results_section.grid_columnconfigure(0, weight=1)

        # Section title
        title = ctk.CTkLabel(
            self.results_section,
            text="📊 Results",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        title.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))

        # Results text area
        self.results_text = ctk.CTkTextbox(
            self.results_section,
            height=200,
            corner_radius=8,
            font=ctk.CTkFont(size=12, family="Courier"),
            fg_color=self.colors["bg_tertiary"],
            state="disabled"
        )
        self.results_text.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))

    def create_footer(self):
        """Create application footer"""
        footer = ctk.CTkFrame(self, fg_color=self.colors["bg_secondary"], corner_radius=0, height=40)
        footer.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        footer.grid_columnconfigure(0, weight=1)
        footer.grid_propagate(False)

        brand_label = ctk.CTkLabel(
            footer,
            text=BRAND,
            font=ctk.CTkFont(size=11),
            text_color=self.colors["text_secondary"]
        )
        brand_label.grid(row=0, column=0, pady=10)

    def browse_file(self):
        """Open file dialog to select input file"""
        file_path = filedialog.askopenfilename(
            title="Select ULP/combos text file",
            filetypes=[("Text files", "*.txt *.csv"), ("All files", "*.*")]
        )

        if file_path:
            self.selected_file = file_path
            # Show filename
            filename = os.path.basename(file_path)
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            self.file_label.configure(
                text=f"✓ {filename} ({size_mb:.1f} MB)",
                text_color=self.colors["success"]
            )

    def load_saved_domains(self):
        """Load saved domains into the text field"""
        saved = load_saved_domains()
        if saved:
            self.domain_input.delete("1.0", "end")
            self.domain_input.insert("1.0", ", ".join(saved))
            self.show_message("Loaded saved domains", "success")
        else:
            self.show_message("No saved domains found", "warning")

    def save_domains_list(self):
        """Save domains from text field"""
        domains_text = self.domain_input.get("1.0", "end").strip()
        if not domains_text:
            self.show_message("Please enter domains to save", "warning")
            return

        domains = [d.strip() for d in domains_text.split(',') if d.strip()]
        if save_domains(domains):
            self.show_message(f"Saved {len(domains)} domains", "success")
        else:
            self.show_message("Failed to save domains", "danger")

    def show_message(self, message: str, msg_type: str = "info"):
        """Show a temporary message"""
        color_map = {
            "success": self.colors["success"],
            "warning": self.colors["warning"],
            "danger": self.colors["danger"],
            "info": self.colors["accent"]
        }

        self.progress_label.configure(
            text=message,
            text_color=color_map.get(msg_type, self.colors["text_secondary"])
        )

    def start_processing(self):
        """Start the processing in a separate thread"""
        if self.processing:
            return

        # Validation
        if not self.selected_file:
            self.show_message("⚠ Please select a file first", "danger")
            return

        if not os.path.exists(self.selected_file):
            self.show_message("⚠ Selected file does not exist", "danger")
            return

        # Get domains
        domains_text = self.domain_input.get("1.0", "end").strip()
        if not domains_text:
            self.show_message("⚠ Please enter domains", "danger")
            return

        domains = [d.strip() for d in domains_text.split(',') if d.strip()]
        self.domains_to_use = [effective_domain(d) for d in domains if d]
        self.domains_to_use = [d for d in self.domains_to_use if d and d != "unknown"]

        if not self.domains_to_use:
            self.show_message("⚠ No valid domains found", "danger")
            return

        # Disable button
        self.processing = True
        self.start_btn.configure(state="disabled", text="⏳ Processing...")
        self.progress.set(0)

        # Start processing in thread
        thread = threading.Thread(target=self.process_file, daemon=True)
        thread.start()

    def process_file(self):
        """Process the file (runs in separate thread)"""
        try:
            # Prepare output directory
            ts = time.strftime("%Y%m%d_%H%M%S")
            out_dir = f"{OUTPUT_PREFIX}_{ts}"
            os.makedirs(out_dir, exist_ok=True)

            db_path = os.path.join(out_dir, DB_NAME)
            invalid_path = os.path.join(out_dir, "invalid_lines.txt")

            # Process file
            mode = self.sorting_mode.get()
            total_bytes = os.path.getsize(self.selected_file)
            processed_bytes = 0

            self.after(0, lambda: self.show_message("Processing file...", "info"))

            import codecs
            def stream_lines(fh):
                decoder = codecs.getincrementaldecoder('utf-8')('ignore')
                buf = b''
                for chunk in iter(lambda: fh.read(1024*1024), b''):
                    buf += chunk
                    while True:
                        nl = buf.find(b'\n')
                        if nl == -1:
                            break
                        line_b, buf = buf[:nl+1], buf[nl+1:]
                        yield decoder.decode(line_b)
                if buf:
                    yield decoder.decode(buf)

            with closing(sqlite3.connect(db_path)) as conn, \
                 open(invalid_path, 'a', encoding='utf-8') as invalid_f:

                conn.executescript(DDL)
                cur = conn.cursor()
                batch = []

                with open(self.selected_file, 'rb') as fh:
                    conn.execute("BEGIN IMMEDIATE")

                    for line in stream_lines(fh):
                        by = len(line.encode('utf-8', 'ignore'))
                        processed_bytes += by

                        # Update progress
                        progress = processed_bytes / total_bytes
                        self.after(0, lambda p=progress: self.progress.set(p))

                        parsed = parse_line(line)
                        if not parsed:
                            invalid_f.write(line.strip() + "\n")
                            continue

                        service, username, password = parsed

                        # Filter based on mode
                        if mode == "email" and not is_email(username):
                            continue
                        elif mode == "number" and not (is_phone_like(username) or is_numeric_id(username)):
                            continue
                        elif mode == "all" and not (is_email(username) or is_phone_like(username) or is_numeric_id(username)):
                            continue

                        domain = effective_domain(service)
                        if domain not in self.domains_to_use:
                            continue

                        batch.append((domain, username, password))
                        if len(batch) >= BATCH_SIZE:
                            cur.executemany(UPSERT_SQL, batch)
                            batch.clear()

                    if batch:
                        cur.executemany(UPSERT_SQL, batch)
                    conn.commit()

            # Generate results
            summary = []
            with closing(sqlite3.connect(db_path)) as conn:
                cur = conn.cursor()
                for domain, founds, uniqs, dups in cur.execute(SELECT_SUMMARY):
                    out_path = os.path.join(out_dir, f"{domain}.txt")
                    with open(out_path, 'w', encoding='utf-8') as df:
                        for u, pw in conn.execute(SELECT_DOMAIN_ROWS, (domain,)):
                            df.write(f"{u}:{pw}\n")
                    dup_pct = int(round((dups/founds)*100)) if founds else 0
                    summary.append((domain, founds, dups, dup_pct, uniqs))

            # Display results
            self.after(0, lambda: self.display_results(out_dir, summary, mode))

        except Exception as e:
            self.after(0, lambda: self.show_message(f"⚠ Error: {str(e)}", "danger"))
        finally:
            self.after(0, lambda: self.start_btn.configure(state="normal", text="▶ Start Processing"))
            self.processing = False

    def display_results(self, out_dir: str, summary: list, mode: str):
        """Display processing results"""
        self.progress.set(1.0)
        self.show_message("✓ Processing complete!", "success")

        # Build results text
        results = []
        results.append("=" * 70)
        results.append(f"OUTPUT FOLDER: {out_dir}")
        results.append("=" * 70)
        results.append("")
        results.append(f"{'Domain':<30} {'Found':<10} {'Dups':<10} {'Dup%':<8} {'Uniques':<10}")
        results.append("-" * 70)

        for domain, founds, dups, dup_pct, uniqs in summary:
            results.append(f"{domain:<30} {founds:<10} {dups:<10} {dup_pct}%{'':<6} {uniqs:<10}")

        results.append("-" * 70)
        results.append(f"\nMode: {mode}:pass")
        results.append(f"Domains matched: {len(summary)}")
        results.append(f"\n✓ All files have been saved to: {out_dir}")

        # Display in text area
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "\n".join(results))
        self.results_text.configure(state="disabled")


def main():
    """Run the GUI application"""
    app = ULPToolGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
