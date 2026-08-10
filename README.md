# Hashcatizer 🔓

[![CI](https://github.com/bishwabikash/Hashcatizer/actions/workflows/ci.yml/badge.svg)](https://github.com/bishwabikash/Hashcatizer/actions/workflows/ci.yml)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/bishwabikash/Hashcatizer?utm_source=oss&utm_medium=github&utm_campaign=bishwabikash%2FHashcatizer&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![License](https://img.shields.io/github/license/bishwabikash/Hashcatizer)](LICENSE)

**File-to-Hashcat Converter Suite** — Extract hashes from encrypted files and output them in [hashcat](https://hashcat.net/hashcat/)-compatible format. Written in Rust for maximum speed.

Inspired by the [`*2john` scripts](https://github.com/openwall/john/tree/bleeding-jumbo/run) from [John the Ripper](https://github.com/openwall/john). Full credits in [CREDITS.md](CREDITS.md).

> **Built with [GitHub Copilot](https://github.com/features/copilot) (Claude Sonnet 4.6)** — All Rust source in this repository was authored using GitHub Copilot powered by Claude Sonnet 4.6. Contributors are encouraged to use the same model for consistency when adding converters or fixing parsing logic.

---

## Features

- **Single static binary** — no runtime dependencies, no interpreter required
- **92 converters** covering wallets, password managers, disk encryption, archives, SSH keys, and more
- **Auto-detection** — pass any file and Hashcatizer identifies the format automatically
- **Hash identification** — pass a raw hash string to identify its type and hashcat mode
- **Hashcat hints** — every result includes the exact `hashcat -m <mode>` command to use

---

## Installation

### From crates.io

```bash
cargo install hashcatizer
```

Installs the `hashcatizer` binary into `~/.cargo/bin` (ensure it's on your `PATH`).

### Pre-built binaries

Download the latest release for your platform from the [Releases page](../../releases).

```bash
# Debian / Ubuntu / Kali (recommended)
curl -LO https://github.com/bishwabikash/Hashcatizer/releases/latest/download/hashcatizer-linux-x86_64.deb
sudo dpkg -i hashcatizer-linux-x86_64.deb

# Linux (musl static tarball)
curl -Lo hashcatizer-linux-x86_64.tar.gz https://github.com/bishwabikash/Hashcatizer/releases/latest/download/hashcatizer-linux-x86_64.tar.gz
tar -xzf hashcatizer-linux-x86_64.tar.gz
chmod +x hashcatizer
sudo mv hashcatizer /usr/local/bin/
```

### Build from source

Requires [Rust](https://rustup.rs/) 1.75+.

```bash
git clone https://github.com/bishwabikash/Hashcatizer.git
cd Hashcatizer
cargo build --release
# Binary: target/release/hashcatizer
```

---

## Usage

```bash
# Auto-detect format and extract hash
hashcatizer <file>

# Use explicit converter
hashcatizer <converter> <file>

# Identify a raw hash string
hashcatizer '<hash_string>'

# List all converters with hashcat mode info
hashcatizer --list
```

### Examples

```bash
# SSH private key → hash + crack command
hashcatizer id_rsa

# Explicit converter
hashcatizer keepass vault.kdbx
hashcatizer pdf document.pdf
hashcatizer ethereum keystore.json
hashcatizer ansible vault.yml

# Pipe straight into hashcat
hashcatizer id_rsa | hashcat -m 22931 -a 0 rockyou.txt
hashcatizer vault.kdbx | hashcat -m 13400 -a 0 rockyou.txt

# Identify a hash you already have
hashcatizer '$2a$12$LlMILsdbh1gAdLhWBXWzXu...'
# → bcrypt (hashcat -m 3200)
```

---

## Correctness

Formats here were reverse-engineered by the John the Ripper project, so JtR's
`*2john` extractors are the reference implementation. `tools/difftest.sh`
generates real encrypted fixtures and compares our output against them
**byte for byte** — the strongest correctness signal available without a GPU.

```bash
cargo build --release
tools/fetch_jtr.sh                  # pulls the *2john extractors (GPL, not vendored)
tools/make_fixtures.sh fixtures     # generates real encrypted test files
tools/difftest.sh fixtures
```

Verified byte-identical to JtR: `7z` (5 archive layouts), `ssh` (PEM + all
OpenSSH key types), `zip`, `gpg`, `ansible`, `openssl`, `pem`, `sipdump`,
`staroffice`, `pfx`, `keystore`.

`bestcrypt` is verified differently: John's format source ships nine test
vectors taken from real containers, so `tools/bestcrypt_roundtrip.py` rebuilds
a container from each vector's fields and checks the extractor reproduces it.
All nine round-trip byte-identically, covering SHA-256, SHA-512 and
Whirlpool-512 with both CBC and XTS.

Implemented against the JtR reference but without a local fixture to diff
against (correct by construction, not yet by measurement): `truecrypt`, `veracrypt`, `diskcryptor`, `geli`, `telegram`, `kirbi`,
`keychain`, `ecryptfs`, `androidbackup`, `multibit`, `andotp`,
`dashlane`, `enpass`, `monero`, `htdigest`, `kdcdump`, `aix`, `prosody`,
`ejabberd`, `ikescan`, `netntlm`, `known_hosts`, `radius`, `hccapx`,
`openbsd_softraid`, `lotus`, `strip`, `atmail`, `network`, `vdi`, `fvde`,
`coinomi`, `dpapimk`, `kwallet`, `ccache`, `signal`.

Formats whose headers are fully encrypted (`truecrypt`, `veracrypt`, `enpass`,
`strip`, `andotp`, `dashlane`, `diskcryptor`) carry no magic bytes, so they are
gated on Shannon entropy plus structural constraints — sector alignment, page
multiples, GCM framing — instead. That cut their false-positive rate from 5/5
to 1/5 against the decoy corpus. The residual case is uniform random input,
which genuinely is indistinguishable from an encrypted header; they remain out
of the auto-detect sweep for that reason.

> **Status:** every converter now parses its format. No converter returns a
> fixed-length hex dump — those produce well-formed
> output that **will not crack**. A converter is only trustworthy once it
> appears in the verified list above. Contributions welcome; follow the
> differential-testing workflow rather than eyeballing the output.

Every mode number in the table below is checked against hashcat's own
`docs/hashcat-example-hashes.md`, both that the mode exists and that its name
matches the format claimed. That check found ten rows citing a real mode
belonging to an unrelated format — `signal` pointed at MS Office
SheetProtection, `zed` at VeraCrypt, the three PGP converters at Telegram
Desktop — which is worse than no mode at all, since the command looks valid and
simply never cracks. All are corrected.

Entries marked `—` are formats hashcat has no kernel for. Hashcatizer still
extracts them, in JtR encoding, and says so at runtime rather than printing a
`-m` that cannot work.

### Upstream work

Gaps found here that belong in hashcat rather than in this tool are fixed
there. Currently open:

| | |
|---|---|
| [hashcat#4767](https://github.com/hashcat/hashcat/pull/4767) | `-m 37500`, a GPU kernel for OpenSSH bcrypt-pbkdf keys — the format `ssh-keygen` has produced by default since 2018, which hashcat had no mode for |
| [hashcat#4766](https://github.com/hashcat/hashcat/pull/4766) | `-m 24420` rejected the `$PEM$2` layout `pem2john.py` emits ([#4765](https://github.com/hashcat/hashcat/issues/4765)) |
| [hashcat#4768](https://github.com/hashcat/hashcat/pull/4768) | combinator attacks reported a plaintext truncated to 256 chars that did not match the cracked digest ([#4042](https://github.com/hashcat/hashcat/issues/4042)) |

Background reading in [`docs/`](docs):

- [HASHCAT_GAPS.md](docs/HASHCAT_GAPS.md) — formats hashcat cannot crack, ranked
- [HASHCAT_SSH_BCRYPT_MODE.md](docs/HASHCAT_SSH_BCRYPT_MODE.md) — design and implementation notes for `-m 37500`
- [RESEARCH_SSH_KEY_CRACKING.md](docs/RESEARCH_SSH_KEY_CRACKING.md) — measured attack economics for modern SSH keys

---

## Supported Formats (92 Converters)

| Converter | Hashcat Mode(s) | Description |
|---|---|---|
| `ssh` | 22911–22951 | SSH private keys. **Modern OpenSSH bcrypt-pbkdf keys are john-only** in released hashcat — [a kernel for them is proposed upstream](https://github.com/hashcat/hashcat/pull/4767) |
| `pdf` | 10400–10700 | PDF 1.1–2.0 |
| `office` | 9400–9800 | MS Office 97–2013+ |
| `keepass` | 13400 | KeePass 1.x / 2.x |
| `bitlocker` | 22100 | BitLocker volumes |
| `truecrypt` | 29311–29343 | TrueCrypt volumes (legacy: 6211–6243) |
| `veracrypt` | 29411–29483 | VeraCrypt volumes (legacy: 13711–13783) |
| `luks` | 14600, 29511–29543 | LUKS v1 encrypted volumes |
| `ethereum` | 15600, 15700 | Ethereum wallets (scrypt / pbkdf2) |
| `bitcoin` | 11300 | Bitcoin / Litecoin wallet.dat |
| `electrum` | 16600, 21700, 21800 | Electrum wallets (salt-type 1–5) |
| `blockchain` | 12700, 15200, 34700 | Blockchain.com wallets |
| `ansible` | 16900 | Ansible Vault |
| `bitwarden` | 23400 | Bitwarden |
| `lastpass` | 6800 | LastPass |
| `1password` | 6600, 8200 | 1Password (agilekeychain / cloudkeychain) |
| `pwsafe` | 5200 | Password Safe v3 |
| `encfs` | — | EncFS — no hashcat kernel |
| `dmg` | — | Apple DMG encrypted images — no hashcat kernel |
| `mozilla` | 26000/26100 | Firefox / Thunderbird key3.db / key4.db |
| `telegram` | 22600, 24500, 22301 | Telegram Desktop (22301 = mobile passcode) |
| `signal` | — | Signal Desktop / Android — no hashcat kernel |
| `7z` | 11600 | 7-Zip archives |
| `zip` | 13600 | WinZip AES-encrypted ZIP |
| `rar` | 12500, 13000, 23700 | RAR3 (-hp / -p) and RAR5 archives |
| `gpg` | 17010–17040 | GnuPG / OpenPGP secret keys |
| `pgpdisk` | — | PGP Virtual Disk — no hashcat kernel |
| `pgpsda` | — | PGP Self-Decrypting Archives — no hashcat kernel |
| `pgpwde` | — | PGP Whole Disk Encryption — no hashcat kernel |
| `zed` | — | ZED / AxCrypt containers — no hashcat kernel |
| `mac` | 7100 | macOS password hashes |
| `lion` | 7100 | macOS Lion SHA-512 (emits `$ml$` form) |
| `pcap` | 22000, 5500, 5600 | PCAP / PCAPNG (WPA, NetNTLM) |
| `netntlm` | 5500, 5600 | NetNTLMv1/v2 |
| `network` | — | Network capture credential hashes |
| `cisco` | 500, 9200, 9300 | Cisco IOS configs |
| `sap` | 7700, 7800 | SAP CODVN B/F/G |
| `ldif` | various | LDAP LDIF hashes |
| `mongodb` | 24100, 24200 | MongoDB SCRAM-SHA-1/256 |
| `ios` | 14800 | iOS / iTunes backup encryption |
| `vdi` | 27500/27600 | VirtualBox disk encryption |
| `androidbackup` | 18900 | Android ADB backup |
| `androidfde` | 12900 | Android Full-Disk Encryption |
| `axcrypt` | 13200 | AxCrypt |
| `bestcrypt` | 23900/24000 | BestCrypt v3/v4 volumes |
| `cardano` | — | Cardano wallets |
| `coinomi` | — | Coinomi wallets |
| `dashlane` | — | Dashlane vaults |
| `deepsound` | — | DeepSound audio steganography |
| `diskcryptor` | 20011–20013 | DiskCryptor volumes |
| `dpapimk` | 15300, 15900 | Windows DPAPI Master Keys |
| `ecryptfs` | 12200 | eCryptfs |
| `enpass` | — | Enpass |
| `fvde` | 16700 | FileVault 2 / Core Storage |
| `geli` | — | FreeBSD GELI |
| `htdigest` | — | Apache htdigest |
| `hccapx` | 22000 | WPA2 HCCAPX |
| `iwork` | 23300 | Apple iWork (Pages/Numbers/Keynote) |
| `keychain` | 23100 | macOS Keychain |
| `keyring` | — | GNOME Keyring |
| `known_hosts` | — | SSH known_hosts (hashed) |
| `libreoffice` | 18400 | LibreOffice / ODF documents |
| `monero` | — | Monero wallets |
| `multibit` | 22500/27700 | MultiBit wallets |
| `openbsd_softraid` | — | OpenBSD softraid crypto |
| `openssl` | — | OpenSSL `enc` (Salted__) |
| `pem` | 24410/24420 | Encrypted PKCS#8 private keys |
| `pfx` | — | PKCS#12 / PFX |
| `restic` | — | Restic repos |
| `staroffice` | — | StarOffice / OOo documents |
| `strip` | — | Strip password manager |
| `tezos` | — | Tezos wallets |
| `vmx` | 27400 | VMware VMX encryption |
| `aix` | — | AIX password hashes |
| `atmail` | — | Atmail webmail hashes |
| `andotp` | — | andOTP backups |
| `applenotes` | — | Apple Notes (encrypted) |
| `bks` | — | Bouncy Castle BKS keystore |
| `ccache` | — | Kerberos ccache |
| `ejabberd` | 23200 | ejabberd SCRAM hashes |
| `gitea` | — | Gitea password hashes |
| `ikescan` | 5300/5400 | ike-scan IKE PSK hashes |
| `kdcdump` | — | KDC key dump |
| `keystore` | 15500 | Java KeyStore (JKS) |
| `keplr` | — | Keplr wallet |
| `kirbi` | 13100 | Kerberos tickets (kirbi) |
| `krb` | 7500, 13100, 18200, 19600–19900 | Kerberos 5 AS-REQ / AS-REP / TGS-REP |
| `kwallet` | — | KDE KWallet |
| `lotus` | 8600/8700/9100 | Lotus Notes / Domino 5, 6, 8 ID files |
| `prosody` | 23200 | Prosody XMPP SCRAM hashes |
| `radius` | — | RADIUS hashes |
| `sipdump` | 11400 | SIP digest auth |

---

## License

Free to use, modify, and distribute under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Credits

Inspired by the `*2john` scripts from [openwall/john](https://github.com/openwall/john), built to complement [hashcat](https://github.com/hashcat/hashcat) by **Jens "atom" Steube**. See [CREDITS.md](CREDITS.md) for full attribution.
