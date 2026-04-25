#!/usr/bin/env python3
"""
Convert VME98/jinx-rules to Surge rule-set format.
"""

import re
import sys
import pathlib


def is_comment_or_empty(line):
    s = line.strip()
    return not s or s.startswith('#')


def is_wildcard_domain(s):
    return '*' in s


def is_full_url(s):
    return s.startswith('http://') or s.startswith('https://')


def strip_known_prefixes(domain):
    return re.sub(r'^DOMAIN[-A-Z]*,', '', domain)


def escape_url_to_regex(pattern):
    parts = pattern.split('*')
    escaped_parts = [re.escape(p) for p in parts]
    escaped = '[^/]*'.join(escaped_parts)

    if is_full_url(pattern):
        result = '^' + escaped
    else:
        result = '^https?://[^/]+' + escaped

    if not result.endswith('[^/]*'):
        result += '(/.*)?$'

    return result


def convert_domain_list(lines):
    out = []
    for raw in lines:
        line = raw.strip()
        if is_comment_or_empty(line):
            continue
        if is_full_url(line):
            continue
        line = strip_known_prefixes(line)
        if not line:
            continue
        if is_wildcard_domain(line):
            continue
        out.append(f'DOMAIN,{line}')
    return out


def convert_wildcard_list(lines):
    out = []
    for raw in lines:
        line = raw.strip()
        if is_comment_or_empty(line):
            continue
        if is_full_url(line):
            continue
        line = strip_known_prefixes(line)
        if not line:
            continue
        out.append(f'DOMAIN-WILDCARD,{line}')
    return out


def convert_url_rules(lines):
    out = []
    for raw in lines:
        line = raw.strip()
        if is_comment_or_empty(line):
            continue

        if re.match(r'^\.[a-zA-Z0-9_-]+\.$', line):
            seg = re.escape(line)
            out.append(f'URL-REGEX,^https?://[^/]*{seg}[^/]*/')
            continue

        if is_full_url(line) or line.startswith('/'):
            pattern = escape_url_to_regex(line)
            out.append(f'URL-REGEX,{pattern}')
            continue

        if '/' in line:
            pattern = escape_url_to_regex('/' + line)
            out.append(f'URL-REGEX,{pattern}')
            continue

    return out


def convert_mitm_skip(lines):
    domains = []
    for raw in lines:
        line = raw.strip()
        if is_comment_or_empty(line):
            continue
        domains.append(f'-{line}')

    hostname_val = '%APPEND% ' + ', '.join(domains)
    return (
        '#!name=Jinx MitM Skip Domains\n'
        '#!desc=Auto-generated from VME98/jinx-rules\n'
        '#!system=ios\n'
        '\n'
        '[MITM]\n'
        f'hostname = {hostname_val}\n'
    )


def make_header(source_file):
    return (
        f'# Auto-generated from VME98/jinx-rules/{source_file}\n'
        '# Do not edit manually.\n'
    )


# ---------------------------------------------------------------------------
# Dedup helpers
# ---------------------------------------------------------------------------

def extract_domain_value(rule):
    """'DOMAIN,foo.com' -> 'foo.com'"""
    if ',' in rule:
        return rule.split(',', 1)[1]
    return rule


def wildcard_to_regex(pattern):
    """
    Convert a DOMAIN-WILDCARD pattern to a compiled regex that matches
    full domain strings.
    e.g. '*.tanx.com' -> regex matching 'wagbridge.alsc-prd.tanx.com' etc.
    """
    parts = pattern.split('*')
    escaped = '.*'.join(re.escape(p) for p in parts)
    return re.compile('^' + escaped + '$', re.IGNORECASE)


def domain_is_covered_by_wildcard(domain, wildcard_pattern):
    """
    Return True if `domain` is fully covered by `wildcard_pattern`.
    e.g. domain='wagbridge.alsc-prd.tanx.com', wildcard='*.tanx.com' -> True
    Also returns True for exact match after stripping leading '*.'
    """
    rx = wildcard_to_regex(wildcard_pattern)
    return bool(rx.match(domain))


def deduplicate_domain_rules(black_rules, white_rules):
    """
    Given two lists of 'DOMAIN,xxx' or 'DOMAIN-WILDCARD,xxx' rules,
    remove from black_rules any entry that:
      1. Is exactly present in white_rules (same full rule string), OR
      2. Its domain value is covered by a DOMAIN-WILDCARD in white_rules, OR
      3. Its DOMAIN-WILDCARD pattern covers (or equals) a domain in white_rules
         — i.e. black wildcard would swallow a white entry.

    Returns cleaned black_rules list.
    """
    white_domains = set()
    white_wildcards = []

    for r in white_rules:
        val = extract_domain_value(r)
        if r.startswith('DOMAIN-WILDCARD,'):
            white_wildcards.append(val)
        else:
            white_domains.add(val)

    clean = []
    for r in black_rules:
        # Exact duplicate
        if r in white_rules:
            continue

        val = extract_domain_value(r)

        if r.startswith('DOMAIN-WILDCARD,'):
            # Black wildcard covers a white domain?
            swallows_white = any(
                domain_is_covered_by_wildcard(wd, val) for wd in white_domains
            )
            # Black wildcard overlaps a white wildcard exactly?
            exact_white_wildcard = val in white_wildcards
            if swallows_white or exact_white_wildcard:
                continue
        else:
            # Black domain covered by a white wildcard?
            covered = any(
                domain_is_covered_by_wildcard(val, ww) for ww in white_wildcards
            )
            # Black domain exact match in white domains?
            exact = val in white_domains
            if covered or exact:
                continue

        clean.append(r)

    return clean


def url_regex_is_duplicate(black_rule, white_rules_set):
    """Exact string match only for URL-REGEX rules."""
    return black_rule in white_rules_set


def deduplicate_url_rules(black_rules, white_rules):
    """
    For URL-REGEX rules, only remove exact duplicates from black_rules.
    URL regexes are opaque enough that structural overlap detection is
    not reliable without actually matching traffic.
    """
    white_set = set(white_rules)
    return [r for r in black_rules if not url_regex_is_duplicate(r, white_set)]


# ---------------------------------------------------------------------------

TASKS = [
    ('blacklist.txt',          'blacklist.list',             'domain'),
    ('blacklist_wildcard.txt', 'blacklist_wildcard.list',    'wildcard'),
    ('whitelist.txt',          'whitelist.list',             'domain'),
    ('whitelist_wildcard.txt', 'whitelist_wildcard.list',    'wildcard'),
    ('url_blacklist.txt',      'url_blacklist.list',         'url'),
    ('url_whitelist.txt',      'url_whitelist.list',         'url'),
    ('mitm_skip_domains.txt',  'mitm_skip_domains.sgmodule', 'mitm'),
]

DEDUP_PAIRS = [
    # (black_dst, white_dst, kind, clean_black_dst, clean_white_dst)
    ('blacklist.list',          'whitelist.list',
     'domain',
     'blacklist_clean.list',    'whitelist_clean.list'),

    ('blacklist_wildcard.list', 'whitelist_wildcard.list',
     'domain',
     'blacklist_wildcard_clean.list', 'whitelist_wildcard_clean.list'),

    ('url_blacklist.list',      'url_whitelist.list',
     'url',
     'url_blacklist_clean.list', 'url_whitelist_clean.list'),
]


def read_rules(path):
    """Read non-comment, non-empty lines from a .list file."""
    lines = path.read_text(encoding='utf-8').splitlines()
    return [l for l in lines if l.strip() and not l.strip().startswith('#')]


def run(src_dir, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: convert all source files as before
    for src_name, dst_name, kind in TASKS:
        src_path = src_dir / src_name
        if not src_path.exists():
            print(f'SKIP (not found): {src_name}')
            continue

        lines = src_path.read_text(encoding='utf-8').splitlines()

        if kind == 'domain':
            result = convert_domain_list(lines)
            content = make_header(src_name) + '\n'.join(result) + '\n'
        elif kind == 'wildcard':
            result = convert_wildcard_list(lines)
            content = make_header(src_name) + '\n'.join(result) + '\n'
        elif kind == 'url':
            result = convert_url_rules(lines)
            content = make_header(src_name) + '\n'.join(result) + '\n'
        elif kind == 'mitm':
            content = convert_mitm_skip(lines)

        (out_dir / dst_name).write_text(content, encoding='utf-8')
        print(f'OK: {src_name} -> {dst_name}')

    # Step 2: generate _clean pairs
    for black_dst, white_dst, kind, clean_black, clean_white in DEDUP_PAIRS:
        bp = out_dir / black_dst
        wp = out_dir / white_dst
        if not bp.exists() or not wp.exists():
            print(f'SKIP dedup (missing): {black_dst} or {white_dst}')
            continue

        black_rules = read_rules(bp)
        white_rules = read_rules(wp)

        if kind == 'url':
            clean_black_rules = deduplicate_url_rules(black_rules, white_rules)
        else:
            # domain + wildcard pairs both use domain dedup logic
            # merge both domain and wildcard white rules for cross-type coverage
            clean_black_rules = deduplicate_domain_rules(black_rules, white_rules)

        # White list stays as-is (no reason to remove from whitelist)
        header_b = f'# Deduplicated: {black_dst} (whitelist entries removed)\n# Do not edit manually.\n'
        header_w = f'# Deduplicated: {white_dst} (reference copy)\n# Do not edit manually.\n'

        (out_dir / clean_black).write_text(
            header_b + '\n'.join(clean_black_rules) + '\n', encoding='utf-8'
        )
        (out_dir / clean_white).write_text(
            header_w + '\n'.join(white_rules) + '\n', encoding='utf-8'
        )

        removed = len(black_rules) - len(clean_black_rules)
        print(f'DEDUP: {black_dst} -> {clean_black} ({removed} rules removed)')
        print(f'DEDUP: {white_dst} -> {clean_white} (reference copy)')

    print('Done.')


if __name__ == '__main__':
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path('rules')
    dst = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path('surge')
    run(src, dst)
