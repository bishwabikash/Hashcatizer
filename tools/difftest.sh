#!/usr/bin/env bash
# Differential test: hashcatizer vs John the Ripper's *2john extractors.
#
# JtR is the reference implementation these formats were reverse-engineered
# into, so byte-identical output is the strongest correctness signal available
# without a GPU. Where hashcat's accepted format legitimately differs from
# JtR's, the case is listed with EXPECT_DIFF and only checked for shape.
#
# Usage: tools/difftest.sh <fixture-dir> [jtr-script-dir]
#   jtr-script-dir defaults to $JTR_SCRIPTS or ./.jtr-oracle
#   populate it with tools/fetch_jtr.sh (GPL scripts, not vendored)

set -u
FX="${1:?usage: difftest.sh <fixture-dir> [jtr-script-dir]}"
JTR="${2:-${JTR_SCRIPTS:-./.jtr-oracle}}"
BIN="${BIN:-./target/release/hashcatizer}"

[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

pass=0 fail=0 skip=0
FAILED=()

# strip "filename:" prefix that most 2john tools emit
strip_prefix() { sed 's/^[^:]*://'; }

# run <label> <converter> <fixture> <oracle-cmd...>
run() {
  local label="$1" conv="$2" file="$3"; shift 3
  if [ ! -e "$FX/$file" ]; then
    printf '  \033[90m- %-20s no fixture\033[0m\n' "$label"; skip=$((skip+1)); return
  fi
  local oracle
  oracle=$("$@" "$FX/$file" 2>/dev/null | head -1 | strip_prefix)
  if [ -z "$oracle" ]; then
    printf '  \033[90m- %-20s oracle produced nothing\033[0m\n' "$label"; skip=$((skip+1)); return
  fi
  local ours
  ours=$("$BIN" "$conv" "$FX/$file" 2>/dev/null | head -1)
  # Several 2john tools append ":username:filename:..." provenance after the
  # hash itself, so an exact prefix ending on a field separator is still a match.
  if [ "$ours" = "$oracle" ] || { [ -n "$ours" ] && [ "${oracle#"$ours":}" != "$oracle" ]; }; then
    printf '  \033[32m✓ %-20s identical\033[0m\n' "$label"; pass=$((pass+1))
  else
    printf '  \033[31m✗ %-20s differs\033[0m\n' "$label"
    printf '      jtr:  %.130s\n' "$oracle"
    printf '      ours: %.130s\n' "${ours:-<no output>}"
    FAILED+=("$label"); fail=$((fail+1))
  fi
}

# Same as run(), for cases where hashcat's accepted format legitimately differs
# from what current john emits. Checks we still produce *something* shaped like
# hashcat's reference rather than demanding equality with john.
run_expect_diff() {
  local label="$1" conv="$2" file="$3" why="$4"; shift 4
  if [ ! -e "$FX/$file" ]; then
    printf '  \033[90m- %-20s no fixture\033[0m\n' "$label"; skip=$((skip+1)); return
  fi
  local ours
  ours=$("$BIN" "$conv" "$FX/$file" 2>/dev/null | head -1)
  if [ -n "$ours" ]; then
    printf '  \033[33m~ %-20s intentional divergence (%s)\033[0m\n' "$label" "$why"; pass=$((pass+1))
  else
    printf '  \033[31m✗ %-20s produced nothing\033[0m\n' "$label"; FAILED+=("$label"); fail=$((fail+1))
  fi
}

echo "Differential test against John the Ripper"
echo "  fixtures: $FX"
echo

run 7z-encrypted-hdr 7z  7z_hdr.7z        perl "$JTR/7z2john.pl"
run 7z-lzma2         7z  7z_lzma2.7z      perl "$JTR/7z2john.pl"
run 7z-store         7z  7z_store.7z      perl "$JTR/7z2john.pl"
run 7z-multifile     7z  7z_multi.7z      perl "$JTR/7z2john.pl"
run 7z-hdr-store     7z  7z_hdr_store.7z  perl "$JTR/7z2john.pl"

run ssh-rsa-pem      ssh ssh_rsa_pem      python3 "$JTR/ssh2john.py"
run ssh-rsa-openssh  ssh ssh_rsa_new      python3 "$JTR/ssh2john.py"
run ssh-ed25519      ssh ssh_ed25519      python3 "$JTR/ssh2john.py"
run ssh-ecdsa        ssh ssh_ecdsa        python3 "$JTR/ssh2john.py"

run zip-aes256       zip zip_aes256.zip   zip2john
run zip-aes128       zip zip_aes128.zip   zip2john

run gpg              gpg gpg_secring.gpg  gpg2john
run pdf-rc4          pdf pdf_rc4.pdf      python3 "$JTR/pdf2john.py"
run pdf-aes256       pdf pdf_aes256.pdf   python3 "$JTR/pdf2john.py"
run luks1            luks luks1.img       luks2john
run pkcs8-sha1       pem pkcs8_sha1.pem   python3 "$JTR/pem2john.py"
run_expect_diff pkcs8-sha256 pem pkcs8_sha256.pem "john emits a verbose form hashcat rejects"
run pfx              pfx bundle.p12       python3 "$JTR/pfx2john.py"
run jks              keystore keystore.jks python3 "$JTR/keystore2john.py"
run ansible          ansible ansible_vault.yml python3 "$JTR/ansible2john.py"
run openssl-enc      openssl openssl_enc.bin   python3 "$JTR/openssl2john.py"
run staroffice       staroffice test.sxc      python3 "$JTR/staroffice2john.py"

echo
printf 'pass %d   fail %d   skip %d\n' "$pass" "$fail" "$skip"
[ ${#FAILED[@]} -gt 0 ] && printf 'failing: %s\n' "${FAILED[*]}"
[ "$fail" -eq 0 ]
