#!/usr/bin/env bash
# Generate real encrypted files for differential testing.
#
# Every fixture uses the same password so a cracked hash can be confirmed
# end-to-end. Fixtures whose tooling is missing are skipped, not faked --
# a converter with no fixture is a converter we have not verified.
#
# Usage: tools/make_fixtures.sh [output-dir]

set -u
OUT="${1:-fixtures}"
PASS="hashcat1"
mkdir -p "$OUT"
cd "$OUT" || exit 1

have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '  %-22s %s\n' "$1" "$2"; }

echo "Generating fixtures in $(pwd) (password: $PASS)"

printf 'secret content here for testing purposes\n' > plain.txt
python3 -c "open('big.txt','w').write('lorem ipsum dolor sit amet '*200)" 2>/dev/null

# --- SSH private keys -------------------------------------------------------
if have ssh-keygen; then
  rm -f ssh_rsa_pem ssh_rsa_new ssh_ed25519 ssh_ecdsa ssh_dsa
  ssh-keygen -q -t rsa -b 2048 -m PEM -f ssh_rsa_pem  -N "$PASS" 2>/dev/null
  ssh-keygen -q -t rsa -b 2048        -f ssh_rsa_new  -N "$PASS" 2>/dev/null
  ssh-keygen -q -t ed25519            -f ssh_ed25519  -N "$PASS" 2>/dev/null
  ssh-keygen -q -t ecdsa -b 256       -f ssh_ecdsa    -N "$PASS" 2>/dev/null
  ssh-keygen -q -t dsa                -f ssh_dsa      -N "$PASS" 2>/dev/null
  rm -f ./*.pub
  note ssh "ok"
else note ssh "SKIP (no ssh-keygen)"; fi

# --- 7-Zip ------------------------------------------------------------------
if have 7z; then
  rm -f 7z_hdr.7z 7z_lzma2.7z 7z_store.7z 7z_multi.7z 7z_hdr_store.7z
  7z a -p"$PASS" -mhe=on      7z_hdr.7z       plain.txt >/dev/null 2>&1
  7z a -p"$PASS"              7z_lzma2.7z     plain.txt >/dev/null 2>&1
  7z a -p"$PASS" -mx0         7z_store.7z     plain.txt >/dev/null 2>&1
  7z a -p"$PASS"              7z_multi.7z     plain.txt big.txt >/dev/null 2>&1
  7z a -p"$PASS" -mhe=on -mx0 7z_hdr_store.7z big.txt >/dev/null 2>&1
  note 7z "ok"
else note 7z "SKIP (no 7z)"; fi

# --- ZIP: WinZip AES and legacy ZipCrypto -----------------------------------
if have 7z; then
  rm -f zip_aes256.zip zip_aes128.zip
  7z a -tzip -mem=AES256 -p"$PASS" zip_aes256.zip plain.txt >/dev/null 2>&1
  7z a -tzip -mem=AES128 -p"$PASS" zip_aes128.zip plain.txt >/dev/null 2>&1
  note zip-aes "ok"
fi
if have zip; then
  rm -f zip_crypto.zip zip_crypto_multi.zip
  zip -q -P "$PASS" zip_crypto.zip plain.txt
  zip -q -P "$PASS" zip_crypto_multi.zip plain.txt big.txt
  note zip-crypto "ok"
else note zip-crypto "SKIP (no zip)"; fi

# --- GnuPG secret keyring ---------------------------------------------------
if have gpg; then
  rm -rf gnupghome gpg_secring.gpg
  mkdir -p gnupghome && chmod 700 gnupghome
  gpg --batch --quiet --homedir gnupghome --passphrase "$PASS" \
      --pinentry-mode loopback --quick-generate-key "Fixture <fix@example.com>" \
      rsa2048 sign never >/dev/null 2>&1
  gpg --batch --quiet --homedir gnupghome --passphrase "$PASS" \
      --pinentry-mode loopback --export-secret-keys > gpg_secring.gpg 2>/dev/null
  [ -s gpg_secring.gpg ] && note gpg "ok" || note gpg "SKIP (export failed)"
else note gpg "SKIP (no gpg)"; fi

# --- OpenSSL: PKCS#8, PKCS#12, enc ------------------------------------------
if have openssl; then
  rm -f pkcs8_sha1.pem pkcs8_sha256.pem cert.pem key.pem bundle.p12 openssl_enc.bin
  openssl genrsa -out key.pem 2048 2>/dev/null
  # PBKDF2-HMAC-SHA1 + 3DES  -> hashcat 24410
  openssl pkcs8 -topk8 -in key.pem -out pkcs8_sha1.pem \
      -v2 des3 -v2prf hmacWithSHA1 -passout "pass:$PASS" 2>/dev/null
  # PBKDF2-HMAC-SHA256 + AES -> hashcat 24420
  openssl pkcs8 -topk8 -in key.pem -out pkcs8_sha256.pem \
      -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout "pass:$PASS" 2>/dev/null
  openssl req -x509 -new -key key.pem -out cert.pem -days 2 -subj "/CN=fixture" 2>/dev/null
  openssl pkcs12 -export -inkey key.pem -in cert.pem -out bundle.p12 \
      -passout "pass:$PASS" 2>/dev/null
  openssl enc -aes-256-cbc -pbkdf2 -in plain.txt -out openssl_enc.bin -k "$PASS" 2>/dev/null
  note openssl "ok"
else note openssl "SKIP (no openssl)"; fi

# --- Java KeyStore ----------------------------------------------------------
if have keytool; then
  rm -f keystore.jks keystore.bks
  keytool -genkeypair -keyalg RSA -keysize 2048 -alias fixture \
      -dname "CN=fixture" -validity 2 -keystore keystore.jks \
      -storetype JKS -storepass "$PASS" -keypass "$PASS" >/dev/null 2>&1
  [ -s keystore.jks ] && note jks "ok" || note jks "SKIP (keytool failed)"
else note jks "SKIP (no keytool)"; fi

# --- LUKS -------------------------------------------------------------------
if have cryptsetup; then
  rm -f luks1.img luks2.img
  for v in 1 2; do
    dd if=/dev/zero of="luks$v.img" bs=1M count=32 status=none 2>/dev/null
    printf '%s' "$PASS" | cryptsetup luksFormat --type "luks$v" \
        --batch-mode --pbkdf-force-iterations 1000 \
        ${v:+$( [ "$v" = 2 ] && echo --pbkdf pbkdf2 )} \
        "luks$v.img" - >/dev/null 2>&1 || rm -f "luks$v.img"
  done
  [ -s luks1.img ] && note luks "ok" || note luks "SKIP (luksFormat failed)"
else note luks "SKIP (no cryptsetup)"; fi

# --- PDF --------------------------------------------------------------------
python3 - "$PASS" <<'PY' 2>/dev/null && note pdf "ok" || note pdf "SKIP (pypdf missing)"
import sys
from pypdf import PdfWriter
for name, algo in [("pdf_rc4.pdf","RC4-128"),("pdf_aes256.pdf","AES-256")]:
    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.encrypt(sys.argv[1], algorithm=algo)
    with open(name,"wb") as f: w.write(f)
PY

# --- Ansible Vault ----------------------------------------------------------
python3 - "$PASS" <<'PY' 2>/dev/null && note ansible "ok" || note ansible "SKIP"
import sys, os, hmac, hashlib, binascii
pw = sys.argv[1].encode()
salt = os.urandom(32)
k = hashlib.pbkdf2_hmac('sha256', pw, salt, 10000, 80)
ct = os.urandom(32)
hm = hmac.new(k[32:64], ct, hashlib.sha256).hexdigest()
body = b'\n'.join([binascii.hexlify(salt), hm.encode(), binascii.hexlify(ct)])
blob = binascii.hexlify(body).decode()
lines = [blob[i:i+80] for i in range(0, len(blob), 80)]
open('ansible_vault.yml','w').write("$ANSIBLE_VAULT;1.1;AES256\n" + "\n".join(lines) + "\n")
PY

echo
echo "Fixtures:"
ls -la | tail -n +2
