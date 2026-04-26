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

        # Host fragment like .ads. or .ad.
        if re.match(r'^\.[a-zA-Z0-9_-]+\.$', line):
            seg = re.escape(line)
            out.append(f'URL-REGEX,^https?://[^/]*{seg}[^/]*/')
            continue

        # Full URL or path starting with /
        if is_full_url(line) or line.startswith('/'):
            pattern = escape_url_to_regex(line)
            out.append(f'URL-REGEX,{pattern}')
            continue

        # Path suffix fragment like .splash — matches URLs where path contains .splash
        if re.match(r'^\.[a-zA-Z0-9_-]+$', line):
            seg = re.escape(line)
            out.append(f'URL-REGEX,^https?://[^/]+/.*{seg}(/.*)?$')
            continue

        # gRPC-style: no leading slash but contains /
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
    return ''

# ---------------------------------------------------------------------------
# Dedup helpers
# ---------------------------------------------------------------------------

def extract_domain_value(rule):
    if ',' in rule:
        return rule.split(',', 1)[1]
    return rule


def wildcard_to_regex(pattern):
    parts = pattern.split('*')
    escaped = '.*'.join(re.escape(p) for p in parts)
    return re.compile('^' + escaped + '$', re.IGNORECASE)


def domain_is_covered_by_wildcard(domain, wildcard_pattern):
    rx = wildcard_to_regex(wildcard_pattern)
    return bool(rx.match(domain))


def deduplicate_domain_rules(black_rules, white_rules):
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
        if r in white_rules:
            continue

        val = extract_domain_value(r)

        if r.startswith('DOMAIN-WILDCARD,'):
            swallows_white = any(
                domain_is_covered_by_wildcard(wd, val) for wd in white_domains
            )
            exact_white_wildcard = val in white_wildcards
            if swallows_white or exact_white_wildcard:
                continue
        else:
            covered = any(
                domain_is_covered_by_wildcard(val, ww) for ww in white_wildcards
            )
            exact = val in white_domains
            if covered or exact:
                continue

        clean.append(r)

    return clean


def deduplicate_url_rules(black_rules, white_rules):
    white_set = set(white_rules)
    return [r for r in black_rules if r not in white_set]


# ---------------------------------------------------------------------------
# Manual override helpers
# ---------------------------------------------------------------------------

OVERRIDE_DIR = 'patch'

OVERRIDE_TEMPLATE_HEADER = (
    '# Manual remove list — one rule per line.\n'
    '# Lines added here will be removed from the corresponding _clean file.\n'
    '# This file is never overwritten by the build script.\n'
)

DEDUP_PAIRS = [
    # (black_dst, white_dst, kind, clean_black_dst, override_file)
    ('blacklist.list',          'whitelist.list',
     'domain',
     'blacklist_clean.list',         'blacklist_patch.list'),

    ('blacklist_wildcard.list', 'whitelist_wildcard.list',
     'domain',
     'blacklist_wildcard_clean.list', 'blacklist_wildcard_patch.list'),

    ('url_blacklist.list',      'url_whitelist.list',
     'url',
     'url_blacklist_clean.list',      'url_blacklist_patch.list'),
]

TASKS = [
    ('blacklist.txt',          'blacklist.list',             'domain'),
    ('blacklist_wildcard.txt', 'blacklist_wildcard.list',    'wildcard'),
    ('whitelist.txt',          'whitelist.list',             'domain'),
    ('whitelist_wildcard.txt', 'whitelist_wildcard.list',    'wildcard'),
    ('url_blacklist.txt',      'url_blacklist.list',         'url'),
    ('url_whitelist.txt',      'url_whitelist.list',         'url'),
    ('mitm_skip_domains.txt',  'mitm_skip_domains.sgmodule', 'mitm'),
]


def read_rules(path):
    lines = path.read_text(encoding='utf-8').splitlines()
    return [l for l in lines if l.strip() and not l.strip().startswith('#')]


def ensure_override_template(path):
    """Create an empty patch file with header comment if it doesn't exist."""
    if not path.exists():
        path.write_text(OVERRIDE_TEMPLATE_HEADER, encoding='utf-8')
        print(f'CREATED template: {path}')


def apply_override(clean_rules, override_path):
    """Remove from clean_rules any entry listed in override_path."""
    if not override_path.exists():
        return clean_rules
    remove_set = set(read_rules(override_path))
    if not remove_set:
        return clean_rules
    filtered = [r for r in clean_rules if r not in remove_set]
    removed = len(clean_rules) - len(filtered)
    if removed:
        print(f'PATCH: removed {removed} rules via {override_path.name}')
    return filtered


# ---------------------------------------------------------------------------

def run(src_dir, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    override_dir = out_dir / OVERRIDE_DIR
    override_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: convert all source files
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

    # Step 2: generate deduplicated black lists, then apply manual patches
    for black_dst, white_dst, kind, clean_black, override_file in DEDUP_PAIRS:
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
            clean_black_rules = deduplicate_domain_rules(black_rules, white_rules)

        removed = len(black_rules) - len(clean_black_rules)
        print(f'DEDUP: {black_dst} -> {clean_black} ({removed} rules removed)')

        # Ensure patch template exists (never overwrite if already present)
        override_path = override_dir / override_file
        ensure_override_template(override_path)

        # Apply manual patch
        clean_black_rules = apply_override(clean_black_rules, override_path)

        header_b = ''
        (out_dir / clean_black).write_text(
            header_b + '\n'.join(clean_black_rules) + '\n', encoding='utf-8'
        )

    print('Done.')


if __name__ == '__main__':
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path('rules')
    dst = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path('surge')
    run(src, dst)
