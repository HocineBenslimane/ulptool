#!/usr/bin/env python3
import re

# Test if the new version is skipping more emails than the old version

ARROW_PATTERN = re.compile(r'^\s*\d*\s*[→►▸➔➜➤➡︎⇒⟹]\s*')
NOT_SAVED_PATTERN = re.compile(r'^\[NOT[_\s]SAVED\]$', re.IGNORECASE)
BRACKET_PATTERN = re.compile(r'[\[\]\(\)\{\}<>"\']')
URL_PREFIX = re.compile(r'^(?:https?://|ftp://|www\.)')

def parse_line_old(line):
    """Old version without arrow pattern and NOT_SAVED check"""
    ln = (line or '').strip()
    if not ln: return None

    ln = BRACKET_PATTERN.sub('', ln).strip()
    if not ln: return None
    ln = URL_PREFIX.sub('', ln)

    if ':' in ln:
        parts = ln.split(':')
        if len(parts) >= 3:
            svc, user = parts[0].strip(), parts[1].strip()
            pw = ':'.join(parts[2:]).strip()
            if user and pw: return (svc, user, pw)
        elif len(parts) == 2:
            user, pw = parts[0].strip(), parts[1].strip()
            if user and pw: return ('unknown', user, pw)
    return None

def parse_line_new(line):
    """New version with arrow pattern and NOT_SAVED check (FIXED)"""
    ln = (line or '').strip()
    if not ln: return None

    ln = ARROW_PATTERN.sub('', ln).strip()
    if not ln: return None

    # FIXED: Don't strip brackets from the whole line
    ln = URL_PREFIX.sub('', ln)

    if ':' in ln:
        parts = ln.split(':')
        if len(parts) >= 3:
            svc, user = parts[0].strip(), parts[1].strip()
            pw = ':'.join(parts[2:]).strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return (svc, user, pw)
        elif len(parts) == 2:
            user, pw = parts[0].strip(), parts[1].strip()
            if user and pw and not NOT_SAVED_PATTERN.match(pw):
                return ('unknown', user, pw)
    return None

# Test on first 100 lines of test.txt
old_count = 0
new_count = 0
differences = []

with open('test.txt', 'r', encoding='utf-8', errors='ignore') as f:
    for i, line in enumerate(f, 1):
        if i > 100:
            break

        old_result = parse_line_old(line)
        new_result = parse_line_new(line)

        if old_result:
            old_count += 1
        if new_result:
            new_count += 1

        if old_result != new_result:
            differences.append((i, line.strip()[:60], old_result, new_result))

print(f'Lines tested: 100')
print(f'Old version parsed: {old_count}')
print(f'New version parsed: {new_count}')
print(f'Differences: {len(differences)}')
print()

if differences:
    print('Lines where parsing differs:')
    print('=' * 80)
    for line_num, line_text, old, new in differences[:10]:
        print(f'Line {line_num}: {line_text}')
        print(f'  OLD: {old}')
        print(f'  NEW: {new}')
        print()
