#!/usr/bin/env bash
# Fetch John the Ripper's *2john extractors for differential testing.
#
# These are NOT vendored into the repository on purpose: they are GPL/LGPL
# licensed, and Hashcatizer ships under MIT OR Apache-2.0. They are developer
# test fixtures pulled on demand into a gitignored directory, never linked
# into or redistributed with the binary.
#
# Usage: tools/fetch_jtr.sh [dest]   (default: .jtr-oracle)

set -eu
DEST="${1:-.jtr-oracle}"
REPO="https://api.github.com/repos/openwall/john/contents/run"

mkdir -p "$DEST"
echo "Fetching *2john extractors into $DEST (GPL/LGPL — test-only, not redistributed)"

curl -fsSL "$REPO" | python3 -c "
import json, sys, os, urllib.request
dest = sys.argv[1]
entries = json.load(sys.stdin)
scripts = [e for e in entries if e['name'].endswith(('2john.py', '2john.pl'))]
ok = 0
for e in scripts:
    target = os.path.join(dest, e['name'])
    if os.path.exists(target):
        ok += 1
        continue
    try:
        urllib.request.urlretrieve(e['download_url'], target)
        ok += 1
    except Exception as exc:
        print(f'  failed: {e[\"name\"]}: {exc}', file=sys.stderr)
print(f'  {ok} extractors available')
" "$DEST"
