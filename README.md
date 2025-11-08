# ULP Sorter - Modern UI

A powerful credential sorting tool with both CLI and modern GUI interfaces.

## Features

- **PSL-aware domain detection** - Intelligent domain parsing using Public Suffix List
- **Huge-file streaming** - Process files of any size without memory issues
- **Disk-based deduplication** - Efficient duplicate detection using SQLite
- **Modern GUI** - Beautiful dark-themed interface inspired by Apple's design language
- **Multiple sorting modes** - Filter by email, phone, numeric IDs, or accept all

## Installation

Install required dependencies:

```bash
pip install customtkinter pillow rich tldextract
```

## Usage

### GUI Mode (Recommended)

Launch the modern graphical interface:

```bash
python ulptool_gui.py
```

**Features:**
- 🎨 Dark theme with rounded buttons and Apple-inspired design
- 📁 Easy file selection with visual feedback
- 🔍 Interactive sorting mode selection
- 🌐 Domain management with save/load functionality
- 📊 Real-time progress tracking
- ✨ Beautiful results display

### CLI Mode

For terminal usage:

```bash
python ulptool.py
```

## How It Works

1. **Select Input File** - Choose your ULP/combos text file
2. **Choose Sorting Mode**:
   - **Email:Pass** - Only email addresses
   - **Phone/Number:Pass** - Phone numbers and numeric IDs
   - **All** - Email, phone, and numeric IDs
   - **Any:Pass** - All usernames (no filtering)
3. **Manage Domains** - Enter target domains (comma-separated)
4. **Process** - Click "Start Processing" and watch the magic happen
5. **View Results** - Check the output folder for sorted credentials

## Output

Results are saved in timestamped folders with format:
```
ULP_Output_YYYYMMDD_HHMMSS/
  ├── domain1.com.txt
  ├── domain2.com.txt
  ├── invalid_lines.txt
  └── work.db
```

Each domain file contains credentials in `username:password` format.

## Supported Input Formats

The tool intelligently parses various credential formats:
- `service|username|password`
- `domain:username:password`
- `username:password`
- `email@domain.com password`
- And many more...

## Credits

Developed by @Timo_Ben

---

Made with ❤️ using CustomTkinter
