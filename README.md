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
`keychain`, `ecryptfs`, `androidbackup`, `multibit`, `andotp`, `dashlane`,
`enpass`, `monero`, `htdigest`, `kdcdump`, `aix`, `prosody`, `ejabberd`,
`ikescan`, `netntlm`, `known_hosts`, `radius`, `hccapx`, `openbsd_softraid`,
`lotus`, `strip`, `atmail`, `network`, `kdcdump`, `vdi`, `fvde`, `coinomi`,
`dpapimk`, `keychain`, `multibit`, `bestcrypt`, `kwallet`, `ccache`, `signal`.

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

Mode numbers in the table below were checked against
`hashcat --example-hashes` (v7.1.2). Entries marked `— (john)` are real formats
that hashcat has no kernel for; the tool tells you so at runtime rather than
printing a `-m` that cannot work.

---

## Supported Formats (92 Converters)

| Converter | Hashcat Mode(s) | Description |
|---|---|---|
| `ssh` | 22911–22951 | SSH private keys. **Modern OpenSSH bcrypt keys are john-only** — hashcat has no kernel for them |
| `pdf` | 10400–10700 | PDF 1.1–2.0 |
| `office` | 9400–9800 | MS Office 97–2013+ |
| `keepass` | 13400 | KeePass 1.x / 2.x |
| `bitlocker` | 22100 | BitLocker volumes |
| `truecrypt` | 29311–29343 | TrueCrypt volumes (legacy: 6211–6243) |
| `veracrypt` | 29411–29483 | VeraCrypt volumes (legacy: 13711–13783) |
| `luks` | 14600 | LUKS encrypted volumes |
| `ethereum` | 15600, 15700 | Ethereum wallets (scrypt / pbkdf2) |
| `bitcoin` | 11300 | Bitcoin / Litecoin wallet.dat |
| `electrum` | 16600 | Electrum wallets |
| `blockchain` | 15200 | Blockchain.com wallets |
| `ansible` | 16900 | Ansible Vault |
| `bitwarden` | 23400 | Bitwarden |
| `lastpass` | 6800 | LastPass |
| `1password` | 8200 | 1Password vaults |
| `pwsafe` | 5200 | Password Safe v3 |
| `encfs` | 6211–6221 | EncFS |
| `dmg` | 12700 | Apple DMG encrypted images |
| `mozilla` | 16600 | Firefox / Thunderbird key3/key4.db |
| `telegram` | 22600/24500 | Telegram Desktop (22301 = mobile passcode) |
| `signal` | 25300 | Signal Desktop / Android |
| `7z` | 11600 | 7-Zip archives |
| `zip` | 13600 | WinZip AES-encrypted ZIP |
| `rar` | 12500, 13000 | RAR3 (-hp) / RAR5 archives |
| `gpg` | 17010 | GnuPG / OpenPGP secret keys |
| `pgpdisk` | 22600 | PGP Virtual Disk |
| `pgpsda` | 22600 | PGP Self-Decrypting Archives |
| `pgpwde` | 22600 | PGP Whole Disk Encryption |
| `zed` | 13711 | ZED / AxCrypt containers |
| `mac` | 7100 | macOS password hashes |
| `lion` | 7100 | macOS Lion SHA-512 |
| `pcap` | 5500, 5600 | PCAP / PCAPNG (NTLM, WPA) |
| `netntlm` | 5500, 5600 | NetNTLMv1/v2 |
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
| `cardano` | — (john) | Cardano wallets |
| `coinomi` | — | Coinomi wallets |
| `dashlane` | — | Dashlane vaults |
| `deepsound` | — (john) | DeepSound audio steganography |
| `diskcryptor` | 20011–20013 | DiskCryptor volumes |
| `dpapimk` | 15300, 15900 | Windows DPAPI Master Keys |
| `ecryptfs` | 12200 | eCryptfs |
| `enpass` | — (john) | Enpass |
| `fvde` | 16700 | FileVault 2 / Core Storage |
| `geli` | — (john) | FreeBSD GELI |
| `htdigest` | — (john) | Apache htdigest |
| `hccapx` | 22000 | WPA2 HCCAPX |
| `iwork` | 23300 | Apple iWork (Pages/Numbers/Keynote) |
| `keychain` | 23100 | macOS Keychain |
| `keyring` | — | GNOME Keyring |
| `known_hosts` | — (john) | SSH known_hosts (hashed) |
| `libreoffice` | 18400 | LibreOffice / ODF documents |
| `monero` | — (john) | Monero wallets |
| `multibit` | 22500/27700 | MultiBit wallets |
| `openbsd_softraid` | — | OpenBSD softraid crypto |
| `openssl` | — (john) | OpenSSL `enc` (Salted__) |
| `pem` | 24410/24420 | Encrypted PKCS#8 private keys |
| `pfx` | — (john) | PKCS#12 / PFX |
| `restic` | — (john) | Restic repos |
| `staroffice` | — (john) | StarOffice / OOo documents |
| `strip` | — (john) | Strip password manager |
| `tezos` | — (john) | Tezos wallets |
| `vmx` | 17300 | VMware VMX encryption |
| `aix` | — | AIX password hashes |
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
| `krb` | — | Kerberos hashes |
| `kwallet` | — | KDE KWallet |
| `lotus` | — | Lotus Notes ID files |
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
