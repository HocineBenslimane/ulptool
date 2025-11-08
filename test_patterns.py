#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test script for the new regex patterns"""

import re

# Pattern definitions
ARROW_PATTERN = re.compile(r'^\s*\d*\s*[→►▸➔➜➤➡︎⇒⟹]\s*')
URL_PREFIX = re.compile(r'^(?:https?://|ftp://|www\.)')
NOT_SAVED_PATTERN = re.compile(r'^\[NOT[_\s]SAVED\]$', re.IGNORECASE)
SUBDOMAIN_EMAIL_PASS = re.compile(r'^([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}):([^:]+):(.+)$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
EMAIL_ENHANCED = re.compile(r'^[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$')
PHONE_LAX_RE = re.compile(r'^[\d\+\-\s\(\)]+$')
NUMERIC_USERNAME = re.compile(r'^\d+[\.\-\d]*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def is_email(s):
    if not s: return False
    return bool(EMAIL_RE.match(s) or EMAIL_ENHANCED.match(s))

def is_phone_like(s):
    if not s or not PHONE_LAX_RE.match(s): return False
    digits = re.sub(r'\D', '', s)
    return 7 <= len(digits) <= 20

def is_numeric_id(s):
    return bool(s and NUMERIC_USERNAME.match(s))

def parse_line(line):
    ln = (line or "").strip()
    if not ln: return None

    # Remove arrow symbols and line numbers
    ln = ARROW_PATTERN.sub('', ln).strip()
    if not ln: return None

    # Remove brackets from beginning/end
    ln = ln.strip('[](){}<>"\'')
    if not ln: return None

    # Strip URL prefixes
    ln = URL_PREFIX.sub('', ln)

    # Try subdomain:email:pass pattern
    match = SUBDOMAIN_EMAIL_PASS.match(ln)
    if match:
        svc, user, pw = match.group(1), match.group(2).strip(), match.group(3).strip()
        if user and pw and not NOT_SAVED_PATTERN.match(pw):
            return (svc, user, pw)

    # Try standard colon separator
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
                return ("unknown", user, pw)

    return None


# Test cases from test.txt
test_cases = [
    ('     4→identity.trimble.com:sylvainrms@gmail.com:*Syl291074',
     'identity.trimble.com', 'sylvainrms@gmail.com', '*Syl291074'),

    ('    63→10.10.10.170:ubnt:charis',
     '10.10.10.170', 'ubnt', 'charis'),

    ('facebook.com:user@email.com:password123',
     'facebook.com', 'user@email.com', 'password123'),

    ('login.live.com:brunoxthe2@hotmail.com:Gato*Mortal00',
     'login.live.com', 'brunoxthe2@hotmail.com', 'Gato*Mortal00'),

    ('com.instagram.android:amiil77_:NemojMePipat12356',
     'com.instagram.android', 'amiil77_', 'NemojMePipat12356'),

    ('auth0.openai.com:exw57qxrhf@hotmail.com:chatgpt@nora',
     'auth0.openai.com', 'exw57qxrhf@hotmail.com', 'chatgpt@nora'),

    ('netflix.com:laurelei67@hotmail.com:a@m$e-n',
     'netflix.com', 'laurelei67@hotmail.com', 'a@m$e-n'),

    ('instagram.com:zoha_n6669:MJdb@hB@MI$$!5x',
     'instagram.com', 'zoha_n6669', 'MJdb@hB@MI$$!5x'),

    ('localhost:diwebd:gggg',
     'localhost', 'diwebd', 'gggg'),

    ('accounts.netgear.com:princekawser@gmail.com:princeNetgear123#',
     'accounts.netgear.com', 'princekawser@gmail.com', 'princeNetgear123#'),
]

print('Testing Enhanced Regex Patterns')
print('=' * 80)

passed = 0
failed = 0

for test_line, expected_domain, expected_user, expected_pass in test_cases:
    result = parse_line(test_line)

    if result:
        domain, user, password = result
        if domain == expected_domain and user == expected_user and password == expected_pass:
            print(f'✓ PASS: {test_line[:50]}...' if len(test_line) > 50 else f'✓ PASS: {test_line}')
            passed += 1
        else:
            print(f'✗ FAIL: {test_line[:50]}...' if len(test_line) > 50 else f'✗ FAIL: {test_line}')
            print(f'  Expected: ({expected_domain}, {expected_user}, {expected_pass})')
            print(f'  Got: ({domain}, {user}, {password})')
            failed += 1
    else:
        print(f'✗ FAIL (no parse): {test_line}')
        failed += 1

print()
print('=' * 80)
print(f'Results: {passed} passed, {failed} failed out of {passed + failed} tests')

# Test validation functions
print()
print('Testing Validation Functions')
print('=' * 80)

validation_tests = [
    ('Email validation', is_email, [
        ('user@example.com', True),
        ('test.user+tag@domain.co.uk', True),
        ('invalid@', False),
        ('notanemail', False),
    ]),
    ('Phone validation', is_phone_like, [
        ('+1234567890', True),
        ('(555) 123-4567', True),
        ('662587668', True),
        ('abc123', False),
    ]),
    ('Numeric ID validation', is_numeric_id, [
        ('1234567890', True),
        ('46.895.401', True),
        ('abc123', False),
        ('user@email.com', False),
    ]),
]

for name, func, tests in validation_tests:
    print(f'\n{name}:')
    for test_val, expected in tests:
        result = func(test_val)
        status = '✓' if result == expected else '✗'
        print(f'  {status} {test_val}: {result} (expected {expected})')

print()
print('=' * 80)
print('Test completed!')
