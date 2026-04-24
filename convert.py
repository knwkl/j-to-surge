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


def is_domain_fragment(s):
    """Lines like .ads. .ad. — dot-wrapped fragments, not valid domains."""
    return re.match(r'^\.[a-zA-Z0-9_-]+\.$', s) is not None


def strip_known_prefixes(domain):
    """Remove accidental DOMAIN, / DOMAIN-SUFFIX, etc. prefixes in source."""
    return re.sub(r'^DOMAIN[-A-Z]*,', '', domain)


def escape_url_to_regex(pattern):
    """
    Convert a URL or path pattern to a URL-REGEX string.
    - Escape regex metacharacters in literal parts
    - Convert * to [^/]*
    - Full URLs get ^ prefix; bare paths get ^https?://[^/]+ prefix
    - Append (/.*)?$ tail unless already ending in wildcard
    """
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
    """blacklist.txt / whitelist.txt -> 'DOMAIN,xxx'"""
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
    """blacklist_wildcard.txt / whitelist_wildcard.txt -> 'DOMAIN-WILDCARD,xxx'"""
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
    """
    url_blacklist.txt / url_whitelist.txt -> mix of URL-REGEX and DOMAIN-WILDCARD lines.
    Handles:
      - Full URLs (with optional * wildcards)
      - Bare paths /xxx
      - Domain fragments .ads. -> DOMAIN-WILDCARD,*ads*
      - gRPC paths (no leading slash but contains /)
    """
    out = []
    for raw in lines:
        line = raw.strip()
        if is_comment_or_empty(line):
            continue

        # Domain fragment like .ads. or .ad.
        if is_domain_fragment(line):
            keyword = line.strip('.')
            out.append(f'DOMAIN-WILDCARD,*{keyword}*')
            continue

        # Full URL or path starting with /
        if is_full_url(line) or line.startswith('/'):
            pattern = escape_url_to_regex(line)
            out.append(f'URL-REGEX,{pattern}')
            continue

        # gRPC-style: no leading slash but contains /
        # e.g. bilibili.community.service.dm.v1.DM/DmView
        if '/' in line:
            pattern = escape_url_to_regex('/' + line)
            out.append(f'URL-REGEX,{pattern}')
            continue

        # Anything else: skip
    return out


def convert_mitm_skip(lines):
    """mitm_skip_domains.txt -> Surge .sgmodule string."""
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


TASKS = [
    ('blacklist.txt',          'blacklist.list',             'domain'),
    ('blacklist_wildcard.txt', 'blacklist_wildcard.list',    'wildcard'),
    ('whitelist.txt',          'whitelist.list',             'domain'),
    ('whitelist_wildcard.txt', 'whitelist_wildcard.list',    'wildcard'),
    ('url_blacklist.txt',      'url_blacklist.list',         'url'),
    ('url_whitelist.txt',      'url_whitelist.list',         'url'),
    ('mitm_skip_domains.txt',  'mitm_skip_domains.sgmodule', 'mitm'),
]


def run(src_dir, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
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

    print('Done.')


if __name__ == '__main__':
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path('rules')
    dst = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path('surge')
    run(src, dst)
