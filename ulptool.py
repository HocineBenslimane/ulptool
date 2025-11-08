#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, sys, json, sqlite3, time, ctypes
from contextlib import closing
from tkinter import Tk, filedialog

APP_NAME = "ULP Sorter"
BRAND    = "Developed by @Timo_Ben"
OUTPUT_PREFIX = "ULP_Output"
DB_NAME = "work.db"
BATCH_SIZE = 5000
PAUSE_ON_EXIT = True

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.expanduser("~"), ".ulp_sorter")
DOMAINS_JSON = os.path.join(APP_DIR, "domains.json")

# ---------- Rich (force terminal) ----------
USE_RICH = False
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.progress import (
        Progress, BarColumn, TextColumn, TimeElapsedColumn,
        TimeRemainingColumn, TransferSpeedColumn
    )
    console = Console(force_terminal=True, legacy_windows=False, highlight=False, soft_wrap=False)
    USE_RICH = True
except Exception:
    console = None

# ---------- tldextract (optional) ----------
try:
    import tldextract
    HAVE_TLDEXTRACT = True
    _extractor = tldextract.TLDExtract(
        cache_dir=os.path.expanduser("~/.tldextract"),
        include_psl_private_domains=True
    )
except Exception:
    HAVE_TLDEXTRACT = False
    _extractor = None

# ---------- WINDOWS: enable ANSI ----------
def _enable_windows_ansi():
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(handle, new_mode)
    except Exception:
        pass
_enable_windows_ansi()

# ---------- Clear helpers ----------
def hard_clear():
    """Be *very* sure the screen is clean (viewport + scrollback)."""
    try:
        if USE_RICH:
            console.clear()
    except Exception:
        pass
    os.system("cls" if os.name == "nt" else "clear")
    try:
        sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
        sys.stdout.flush()
    except Exception:
        pass

def show_header():
    subtitle = "PSL-aware • Huge-file streaming • Disk dedupe • 2026 UI"
    if USE_RICH:
        console.print(Panel.fit(
            f"{subtitle}\n\n[italic]{BRAND}[/italic]",
            title=f"[bold white]{APP_NAME}[/bold white]",
            border_style="white"
        ))
    else:
        print(f"{APP_NAME}\n{subtitle}\n{BRAND}\n")

def pause_and_exit():
    if PAUSE_ON_EXIT:
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass

# ---------- Regex / parsing ----------
# Primary separator pattern (colon, pipe, semicolon, comma)
SEP_PATTERN = re.compile(r'[:\|;,]\s*')
# Tab separator pattern
TAB_PATTERN = re.compile(r'\t+')
# Fallback whitespace split
FALLBACK_SPLIT = re.compile(r'\s+')
# URL prefix pattern (strip http://, https://, etc.)
URL_PREFIX = re.compile(r'^(?:https?://|ftp://|www\.)')
# Email validation
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
# Phone number validation (relaxed)
PHONE_LAX_RE = re.compile(r'^[\d\+\-\s\(\)]+$')
# Pattern to match lines with brackets/quotes around fields
BRACKET_PATTERN = re.compile(r'[\[\]\(\)\{\}<>"\']')
# Pattern to detect and extract from "service|user|pass" or "domain|email|password" format
PIPE_SEP = re.compile(r'\|')
# Pattern for lines like "email@domain.com password123"
EMAIL_SPACE_PASS = re.compile(r'^([^@\s]+@[^@\s]+\.[^@\s]+)\s+(.+)$')
# Pattern for lines like "domain.com:username:password" or "service username password"
DOMAIN_USER_PASS = re.compile(r'^([a-zA-Z0-9\.\-\_]+)\s+([^\s]+)\s+(.+)$')
# Pattern to remove arrow symbols and line numbers (common in leak dumps)
ARROW_PATTERN = re.compile(r'^\s*\d*\s*[→►▸➔➜➤➡︎⇒⟹]\s*')
# Pattern for IP addresses (to detect IP-based domains)
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
# Pattern to match [NOT_SAVED] or similar placeholders
NOT_SAVED_PATTERN = re.compile(r'^\[NOT[_\s]SAVED\]$', re.IGNORECASE)
# Pattern for credentials with subdomain:email:pass format (e.g., login.live.com:user@email.com:pass)
SUBDOMAIN_EMAIL_PASS = re.compile(r'^([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}):([^:]+):(.+)$')
# Pattern for package names like com.facebook.katana or com.instagram.android
PACKAGE_NAME = re.compile(r'^(com|net|org|io)\.[a-zA-Z0-9\.\-_]+$')
# Pattern for numeric usernames (IDs)
NUMERIC_USERNAME = re.compile(r'^\d+[\.\-\d]*$')
# Enhanced pattern for email with special characters in local part
EMAIL_ENHANCED = re.compile(r'^[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$')
# Pattern for credentials with extra fields (e.g., amount or other metadata)
EXTRA_FIELDS = re.compile(r':.*?:.*?:')  # Detects 3+ colons

def is_email(s):
    """Check if string is a valid email address"""
    if not s: return False
    return bool(EMAIL_RE.match(s) or EMAIL_ENHANCED.match(s))

def is_phone_like(s):
    """Check if string looks like a phone number"""
    if not s or not PHONE_LAX_RE.match(s): return False
    digits = re.sub(r'\D', '', s)
    return 7 <= len(digits) <= 20

def is_numeric_id(s):
    """Check if string is a numeric ID"""
    return bool(s and NUMERIC_USERNAME.match(s))

def is_ip_address(s):
    """Check if string is an IP address"""
    if not s: return False
    if IP_ADDRESS.match(s):
        # Validate IP ranges (0-255)
        parts = s.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def is_package_name(s):
    """Check if string is a package name (e.g., com.facebook.katana)"""
    return bool(s and PACKAGE_NAME.match(s))

def pick_file_via_dialog():
    root = Tk(); root.withdraw(); root.attributes('-topmost', True)
    p = filedialog.askopenfilename(
        title="Select ULP/combos text file",
        filetypes=[("Text files","*.txt *.csv"),("All files","*.*")]
    )
    root.destroy(); return p

# ---------- Domain normalization ----------
PKG_ROOTS = {"com","net","org","io","co"}
PKG_TRAILERS = {"android","ios","katana","gm","messenger","mobile","client","app"}

def _package_like_to_domain(s):
    toks=[t for t in s.split('.') if t]
    if len(toks)<2 or toks[0] not in PKG_ROOTS: return None
    brand = toks[2] if len(toks)>=3 and toks[1] in PKG_TRAILERS else toks[1]
    return f"{brand}.com" if re.match(r'^[a-z0-9\-]+$', brand) else None

def effective_domain(token):
    """Extract and normalize the effective domain from various input formats"""
    s=(token or "").strip().lower()
    if not s: return "unknown"

    # Handle IP addresses specially
    if is_ip_address(s):
        return f"ip_{s.replace('.', '_')}"

    # Handle package names (e.g., com.facebook.katana -> facebook.com)
    pkg=_package_like_to_domain(s)
    if pkg: return pkg

    # Use tldextract if available for best results
    if HAVE_TLDEXTRACT:
        ext=_extractor(s)
        if ext.domain and ext.suffix:
            # Include subdomain for certain services (login, auth, api, etc.)
            if ext.subdomain and ext.subdomain in ['login', 'auth', 'api', 'www', 'm', 'mobile', 'accounts', 'signup', 'signin']:
                return f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
            return f"{ext.domain}.{ext.suffix}"

    # Fallback: manual parsing
    s=re.sub(r'[^a-z0-9\.\-]', '.', s)
    parts=[p for p in s.split('.') if p]
    if not parts: return "unknown"

    # Handle country code TLDs (e.g., .co.uk, .com.br)
    if len(parts)>=3 and len(parts[-1])==2 and len(parts[-2])<=3:
        return '.'.join(parts[-3:])

    # Standard domain.tld
    if len(parts)>=2:
        return '.'.join(parts[-2:])

    return parts[0]

def parse_line(line):
    ln=(line or "").strip()
    if not ln: return None

    # Remove arrow symbols and line numbers (common in leak dumps)
    ln = ARROW_PATTERN.sub('', ln).strip()
    if not ln: return None

    # Strip URL prefixes if present
    ln = URL_PREFIX.sub('', ln)

    # Strategy 1: Try pipe separator first (common in dumps: service|user|pass)
    if '|' in ln:
        parts = ln.split('|')
        if len(parts) >= 3:
            svc, user = parts[0].strip(), parts[1].strip()
            pw = '|'.join(parts[2:]).strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return (svc, user, pw)
        elif len(parts) == 2:
            user, pw = parts[0].strip(), parts[1].strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return ("unknown", user, pw)

    # Strategy 2: Try tab separator (TSV format)
    if '\t' in ln:
        parts = TAB_PATTERN.split(ln)
        if len(parts) >= 3:
            svc, user = parts[0].strip(), parts[1].strip()
            pw = '\t'.join(parts[2:]).strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return (svc, user, pw)
        elif len(parts) == 2:
            user, pw = parts[0].strip(), parts[1].strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return ("unknown", user, pw)

    # Strategy 3: Enhanced subdomain:email:pass pattern (e.g., login.live.com:email@domain.com:password)
    match = SUBDOMAIN_EMAIL_PASS.match(ln)
    if match:
        svc, user, pw = match.group(1), match.group(2).strip(), match.group(3).strip()
        if user and pw and not NOT_SAVED_PATTERN.match(pw):
            return (svc, user, pw)

    # Strategy 4: Standard separators (: ; , with optional spaces)
    # Handle multiple colons intelligently (for passwords containing colons)
    if ':' in ln:
        parts = ln.split(':')
        if len(parts) >= 3:
            svc, user = parts[0].strip(), parts[1].strip()
            # Join remaining parts as password (in case password contains colons)
            pw = ':'.join(parts[2:]).strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return (svc, user, pw)
        elif len(parts) == 2:
            # Simple user:pass format
            user, pw = parts[0].strip(), parts[1].strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return ("unknown", user, pw)

    # Strategy 5: Semicolon or comma separators
    for sep_char in [';', ',']:
        if sep_char in ln:
            parts = ln.split(sep_char)
            if len(parts) >= 3:
                svc, user = parts[0].strip(), parts[1].strip()
                pw = sep_char.join(parts[2:]).strip()
                if user and pw and not NOT_SAVED_PATTERN.match(pw):
                    return (svc, user, pw)

    # Strategy 6: Email followed by password (email@domain.com password123)
    match = EMAIL_SPACE_PASS.match(ln)
    if match:
        email, pw = match.group(1), match.group(2).strip()
        if email and pw and not NOT_SAVED_PATTERN.match(pw):
            return ("unknown", email, pw)

    # Strategy 7: Three whitespace-separated fields (domain username password)
    parts2 = FALLBACK_SPLIT.split(ln)
    if len(parts2) >= 3:
        svc, user = parts2[0].strip(), parts2[1].strip()
        pw = ' '.join(parts2[2:]).strip()
        if user and pw and not NOT_SAVED_PATTERN.match(pw):
            return (svc, user, pw)

    # Strategy 8: Two whitespace-separated fields (username password)
    if len(parts2) == 2:
        user, pw = parts2[0].strip(), parts2[1].strip()
        if user and pw and not NOT_SAVED_PATTERN.match(pw):
            return ("unknown", user, pw)

    return None

# ---------- Saved domains ----------
def ensure_app_dir():
    try: os.makedirs(APP_DIR, exist_ok=True)
    except Exception: pass

def load_saved_domains():
    ensure_app_dir()
    if not os.path.exists(DOMAINS_JSON): return []
    try:
        with open(DOMAINS_JSON,"r",encoding="utf-8") as f: data=json.load(f)
        if isinstance(data,list):
            return sorted({effective_domain(str(x)) for x in data if str(x).strip()})
    except Exception: return []
    return []

def save_domains(domains_list):
    ensure_app_dir()
    try:
        norm=sorted({effective_domain(x) for x in domains_list if x})
        with open(DOMAINS_JSON,"w",encoding="utf-8") as f: json.dump(norm,f,ensure_ascii=False,indent=2)
        return True
    except Exception: return False

def prompt_domains_input():
    msg=("Type the domains (comma-separated)\n"
         "Examples: capcut.com, dropbox.com, com.facebook.katana")
    if USE_RICH:
        console.print(Panel.fit(msg, title="Domains", border_style="cyan"))
        raw=Prompt.ask("[bold]Input[/bold]").strip()
    else:
        print(msg); raw=input("> ").strip()
    toks=[t for t in (raw.split(',') if raw else []) if t.strip()]
    norm={effective_domain(t) for t in toks if t.strip()}; norm.discard("unknown")
    return sorted(norm)

def prompt_domain_strategy():
    saved=load_saved_domains()
    if saved:
        options=("1) Use saved list\n"
                 "2) Add/merge new domains into saved list (then use merged)\n"
                 "3) Replace saved list with new domains (then use new)\n"
                 "4) Use a one-time list (do not save)")
        if USE_RICH: console.print(Panel.fit(options, title="Domain list options", border_style="magenta")); ch=Prompt.ask("Choose [1-4]").strip()
        else: print(options); ch=input("> ").strip()
        while ch not in {"1","2","3","4"}:
            (console.print("[red]Please choose 1–4.[/red]") if USE_RICH else print("Please choose 1–4."))
            ch=input("> ").strip()
    else:
        options=("No saved domain list found.\n"
                 "3) Create and use a new saved list\n"
                 "4) Use a one-time list (do not save)")
        if USE_RICH: console.print(Panel.fit(options, title="Domain list options", border_style="magenta")); ch=Prompt.ask("Choose [3-4]").strip()
        else: print(options); ch=input("> ").strip()
        while ch not in {"3","4"}:
            (console.print("[red]Please choose 3 or 4.[/red]") if USE_RICH else print("Please choose 3 or 4."))
            ch=input("> ").strip()
    return ch, saved

# ---------- SQLite ----------
DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;
PRAGMA page_size = 4096;
CREATE TABLE IF NOT EXISTS entries (
  domain TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  cnt INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (domain, username, password)
);
CREATE INDEX IF NOT EXISTS idx_domain ON entries(domain);
"""
UPSERT_SQL = """INSERT INTO entries(domain, username, password, cnt)
VALUES (?, ?, ?, 1)
ON CONFLICT(domain, username, password) DO UPDATE SET cnt = cnt + 1;"""
SELECT_SUMMARY = """
SELECT domain, SUM(cnt) AS founds, COUNT(*) AS uniqs, SUM(cnt)-COUNT(*) AS dups
FROM entries GROUP BY domain ORDER BY founds DESC;"""
SELECT_DOMAIN_ROWS = "SELECT username, password FROM entries WHERE domain = ?;"

def ask_sorting_choice():
    text = "Choose sorting type:\n  1) email:pass\n  2) phone/number:pass\n  3) all (email, phone, numeric IDs)\n  4) user:pass (any username - no filtering)"
    if USE_RICH:
        console.print(Panel.fit(text, title="Sorting", border_style="green"))
        ch=Prompt.ask("Choose [1-4]").strip()
    else:
        print(text); ch=input("> ").strip()
    if ch == "4":
        return "any"
    elif ch == "3":
        return "all"
    elif ch == "2":
        return "number"
    else:
        return "email"

# ---------- Processing ----------
def process_stream(input_path, sorting_mode, domains_to_use, db_path, invalid_path):
    invalid=0; total_bytes=os.path.getsize(input_path)
    import codecs
    def stream_lines(fh):
        decoder = codecs.getincrementaldecoder('utf-8')('ignore'); buf=b''
        for chunk in iter(lambda: fh.read(1024*1024), b''):
            buf+=chunk
            while True:
                nl=buf.find(b'\n')
                if nl==-1: break
                line_b,buf=buf[:nl+1],buf[nl+1:]
                yield decoder.decode(line_b)
        if buf: yield decoder.decode(buf)

    with closing(sqlite3.connect(db_path)) as conn, open(invalid_path,'a',encoding='utf-8') as invalid_f:
        conn.executescript(DDL); cur=conn.cursor(); batch=[]
        if USE_RICH:
            # ensure perfectly clean start before progress draws
            hard_clear(); show_header()
            progress = Progress(
                TextColumn("[bold blue]Processing[/bold blue]"),
                BarColumn(bar_width=None),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                TextColumn("{task.completed:>12,d} / {task.total:>12,d} bytes"),
                TextColumn("•"),
                TransferSpeedColumn(),
                TimeElapsedColumn(), TimeRemainingColumn(),
                transient=True, refresh_per_second=12, console=console
            )
            task = progress.add_task("process", total=total_bytes)
            progress.start()

        with open(input_path,'rb') as fh:
            conn.execute("BEGIN IMMEDIATE")
            for line in stream_lines(fh):
                by=len(line.encode('utf-8','ignore'))
                parsed=parse_line(line)
                if not parsed:
                    invalid+=1; invalid_f.write(line.strip()+"\n")
                    if USE_RICH: progress.update(task, advance=by)
                    continue
                service,username,password=parsed
                # Filter based on sorting mode
                if sorting_mode == "email":
                    if not is_email(username):
                        if USE_RICH: progress.update(task, advance=by)
                        continue
                elif sorting_mode == "number":
                    if not (is_phone_like(username) or is_numeric_id(username)):
                        if USE_RICH: progress.update(task, advance=by)
                        continue
                elif sorting_mode == "all":
                    # Accept email, phone, or numeric ID
                    if not (is_email(username) or is_phone_like(username) or is_numeric_id(username)):
                        if USE_RICH: progress.update(task, advance=by)
                        continue
                # sorting_mode == "any" - accept all usernames, no filtering
                domain=effective_domain(service)
                if domain not in domains_to_use:
                    if USE_RICH: progress.update(task, advance=by); continue
                batch.append((domain,username,password))
                if len(batch)>=BATCH_SIZE:
                    cur.executemany(UPSERT_SQL,batch); batch.clear()
                if USE_RICH: progress.update(task, advance=by)
            if batch: cur.executemany(UPSERT_SQL,batch)
            conn.commit()
        if USE_RICH:
            progress.update(task, completed=total_bytes); progress.stop()
            # clear again after progress removes itself
            hard_clear(); show_header()
    return invalid, total_bytes

# ---------- Main ----------
def main():
    hard_clear(); show_header()
    p=pick_file_via_dialog()
    if not p:
        (console.print("[red]No file selected. Exiting.[/red]") if USE_RICH else print("No file selected."))
        pause_and_exit(); sys.exit(1)
    if not os.path.exists(p):
        (console.print("[red]Selected file does not exist.[/red]") if USE_RICH else print("Selected file does not exist."))
        pause_and_exit(); sys.exit(1)

    mode=ask_sorting_choice()
    hard_clear(); show_header()

    # Domain strategy
    while True:
        choice,saved=prompt_domain_strategy()
        hard_clear(); show_header()
        domains_to_use=[]
        if choice=="1":
            domains_to_use=saved
        elif choice=="2":
            domains=prompt_domains_input()
            while not domains:
                (console.print("[yellow]No valid domains. Try again.[/yellow]") if USE_RICH else print("No valid domains. Try again."))
                domains=prompt_domains_input()
            domains_to_use=sorted(set(saved)|set(domains)); save_domains(domains_to_use)
        elif choice=="3":
            domains=prompt_domains_input()
            while not domains:
                (console.print("[yellow]No valid domains. Try again.[/yellow]") if USE_RICH else print("No valid domains. Try again."))
                domains=prompt_domains_input()
            domains_to_use=domains; save_domains(domains_to_use)
        else:
            domains=prompt_domains_input()
            while not domains:
                (console.print("[yellow]No valid domains. Try again.[/yellow]") if USE_RICH else print("No valid domains. Try again."))
                domains=prompt_domains_input()
            domains_to_use=domains
        domains_to_use=[d for d in domains_to_use if d and d!="unknown"]
        if domains_to_use: break

    # Prepare outputs
    ts=time.strftime("%Y%m%d_%H%M%S")
    out_dir=f"{OUTPUT_PREFIX}_{ts}"; os.makedirs(out_dir, exist_ok=True)
    db_path=os.path.join(out_dir, DB_NAME)
    invalid_path=os.path.join(out_dir, "invalid_lines.txt"); open(invalid_path,'a',encoding='utf-8').close()

    # Save domains used next to script (fallback to output dir if needed)
    try:
        with open(os.path.join(SCRIPT_DIR,"domains_used.json"),"w",encoding="utf-8") as f:
            json.dump(sorted(set(domains_to_use)), f, ensure_ascii=False, indent=2)
    except Exception:
        try:
            with open(os.path.join(out_dir,"domains_used.json"),"w",encoding="utf-8") as f:
                json.dump(sorted(set(domains_to_use)), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # Final pre-process hard clear
    hard_clear(); show_header()
    process_stream(p, mode, set(domains_to_use), db_path, invalid_path)

    # Summaries
    summary=[]
    with closing(sqlite3.connect(db_path)) as conn:
        cur=conn.cursor()
        for domain,founds,uniqs,dups in cur.execute(SELECT_SUMMARY):
            out_path=os.path.join(out_dir,f"{domain}.txt")
            with open(out_path,'w',encoding='utf-8') as df:
                for u,pw in conn.execute(SELECT_DOMAIN_ROWS,(domain,)):
                    df.write(f"{u}:{pw}\n")
            dup_pct=int(round((dups/founds)*100)) if founds else 0
            summary.append((domain,founds,dups,dup_pct,uniqs))

    # Final screen only
    hard_clear(); show_header()
    if USE_RICH:
        console.print(Panel.fit(out_dir, title="Output folder", border_style="white"))
        table=Table(title="Domain summary", show_lines=False, expand=False)
        for c,j in [("Domain",None),("Founds","right"),("Duplicates","right"),("Dup %","right"),("Uniques","right")]:
            table.add_column(c, justify=j or "left", style="bold" if c=="Domain" else None)
        for domain,founds,dups,dup_pct,uniqs in summary:
            table.add_row(domain,str(founds),str(dups),f"{dup_pct}%",str(uniqs))
        console.print(table)
        footer=(f"[bold]Mode[/bold]: {mode}:pass\n"
                f"[bold]Domains matched in file[/bold]: {len(summary)}\n"
                f"[bold]Invalid lines file[/bold]: {invalid_path}\n\n"
                f"[dim]{BRAND}[/dim]")
        console.print(Panel.fit(footer, title="Summary", border_style="green"))
    else:
        print(f"Output folder: {out_dir}\n")
        for domain,founds,dups,dup_pct,uniqs in summary:
            print(f"{domain} - {founds} founds - duplicates {dups} ({dup_pct}%) - uniqs {uniqs}")
        print("\n— Summary —")
        print(f"Mode: {mode}:pass")
        print(f"Domains matched in file: {len(summary)}")
        print(f"Invalid lines file: {invalid_path}")
        print(f"\n{BRAND}")

    pause_and_exit()

if __name__ == "__main__":
    main()
