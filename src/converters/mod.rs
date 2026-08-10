pub mod ansible;
pub mod atmail;
pub mod bitcoin;
pub mod bitlocker;
pub mod bitwarden;
pub mod blockchain;
pub mod cisco;
pub mod dmg;
pub mod electrum;
pub mod encfs;
pub mod ethereum;
pub mod ios;
pub mod keepass;
pub mod lastpass;
pub mod ldif;
pub mod lion;
pub mod luks;
pub mod mac;
pub mod mongodb;
pub mod mozilla;
pub mod netntlm;
pub mod network;
pub mod office;
pub mod onepassword;
pub mod pcap;
pub mod pdf;
pub mod pgpdisk;
pub mod pgpsda;
pub mod pgpwde;
pub mod pwsafe;
pub mod sap;
pub mod sevenz;
pub mod signal;
pub mod ssh;
pub mod telegram;
pub mod truecrypt;
pub mod vdi;
pub mod veracrypt;
pub mod zed;
// batch
pub mod androidbackup;
pub mod androidfde;
pub mod axcrypt;
pub mod bestcrypt;
pub mod cardano;
pub mod coinomi;
pub mod dashlane;
pub mod deepsound;
pub mod diskcryptor;
pub mod dpapimk;
pub mod ecryptfs;
pub mod enpass;
pub mod fvde;
pub mod geli;
pub mod htdigest;
pub mod hccapx;
pub mod iwork;
pub mod keychain;
pub mod keyring;
pub mod known_hosts;
pub mod libreoffice;
pub mod monero;
pub mod multibit;
pub mod openbsd_softraid;
pub mod openssl_enc;
pub mod pem;
pub mod pfx;
pub mod restic;
pub mod staroffice;
pub mod strip;
pub mod tezos;
pub mod vmx;
// extended
pub mod aix;
pub mod andotp;
pub mod applenotes;
pub mod gpg;
pub mod rar;
pub mod zip;
pub mod bks;
pub mod ccache;
pub mod ejabberd;
pub mod gitea;
pub mod ikescan;
pub mod kdcdump;
pub mod keystore_jks;
pub mod kirbi;
pub mod keplr;
pub mod kwallet;
pub mod krb;
pub mod lotus;
pub mod prosody;
pub mod radius;
pub mod sipdump;

/// Convert data/path using the named converter. Returns extracted hash lines.
pub fn run(name: &str, data: &[u8], path: &str) -> Option<Vec<String>> {
    use std::path::Path;
    let filename = path.to_string();
    let fpath = Path::new(path);
    match name {
        "ansible"        => ansible::convert(data, &filename),
        "atmail"         => atmail::convert(data, &filename),
        "bitcoin"        => bitcoin::convert(data, &filename),
        "bitlocker"      => bitlocker::convert(data, &filename),
        "bitwarden"      => bitwarden::convert(data, &filename),
        "blockchain"     => blockchain::convert(data, &filename),
        "cisco"          => cisco::convert(data, &filename),
        "dmg"            => dmg::convert(data, &filename),
        "electrum"       => electrum::convert(data, &filename),
        "encfs"          => encfs::convert(data, &filename),
        "ethereum"       => ethereum::convert(data, &filename),
        "ios"            => ios::convert(fpath),
        "keepass"        => keepass::convert(data, &filename),
        "lastpass"       => lastpass::convert(data, &filename),
        "ldif"           => ldif::convert(data, &filename),
        "lion"           => lion::convert(data, &filename),
        "luks"           => luks::convert(data, &filename),
        "mac"            => mac::convert(data, &filename),
        "mongodb"        => mongodb::convert(data, &filename),
        "mozilla"        => mozilla::convert(fpath),
        "netntlm"        => netntlm::convert(data, &filename),
        "network"        => network::convert(data, &filename),
        "office"         => office::convert(data, &filename),
        "1password"      => onepassword::convert(fpath),
        "pcap"           => pcap::convert(data, &filename),
        "pdf"            => pdf::convert(data, &filename),
        "pgpdisk"        => pgpdisk::convert(data, &filename),
        "pgpsda"         => pgpsda::convert(data, &filename),
        "pgpwde"         => pgpwde::convert(data, &filename),
        "pwsafe"         => pwsafe::convert(data, &filename),
        "sap"            => sap::convert(data, &filename),
        "7z"             => sevenz::convert(data, &filename),
        "signal"         => signal::convert(fpath),
        "ssh"            => ssh::convert(data, &filename),
        "telegram"       => telegram::convert(data, &filename),
        "truecrypt"      => truecrypt::convert(data, &filename),
        "vdi"            => vdi::convert(data, &filename),
        "veracrypt"      => veracrypt::convert(data, &filename),
        "zed"            => zed::convert(data, &filename),
        // batch
        "androidbackup"  => androidbackup::convert(data, &filename),
        "androidfde"     => androidfde::convert(data, &filename),
        "axcrypt"        => axcrypt::convert(data, &filename),
        "bestcrypt"      => bestcrypt::convert(data, &filename),
        "cardano"        => cardano::convert(data, &filename),
        "coinomi"        => coinomi::convert(data, &filename),
        "dashlane"       => dashlane::convert(data, &filename),
        "deepsound"      => deepsound::convert(data, &filename),
        "diskcryptor"    => diskcryptor::convert(data, &filename),
        "dpapimk"        => dpapimk::convert(data, &filename),
        "ecryptfs"       => ecryptfs::convert(data, &filename),
        "enpass"         => enpass::convert(data, &filename),
        "fvde"           => fvde::convert(data, &filename),
        "geli"           => geli::convert(data, &filename),
        "htdigest"       => htdigest::convert(data, &filename),
        "hccapx"         => hccapx::convert(data, &filename),
        "iwork"          => iwork::convert(data, &filename),
        "keychain"       => keychain::convert(data, &filename),
        "keyring"        => keyring::convert(data, &filename),
        "known_hosts"    => known_hosts::convert(data, &filename),
        "libreoffice"    => libreoffice::convert(data, &filename),
        "monero"         => monero::convert(data, &filename),
        "multibit"       => multibit::convert(data, &filename),
        "openbsd_softraid" => openbsd_softraid::convert(data, &filename),
        "openssl"        => openssl_enc::convert(data, &filename),
        "pem"            => pem::convert(data, &filename),
        "pfx"            => pfx::convert(data, &filename),
        "restic"         => restic::convert(data, &filename),
        "staroffice"     => staroffice::convert(data, &filename),
        "strip"          => strip::convert(data, &filename),
        "tezos"          => tezos::convert(data, &filename),
        "vmx"            => vmx::convert(data, &filename),
        // extended
        "aix"            => aix::convert(data, &filename),
        "andotp"         => andotp::convert(data, &filename),
        "applenotes"     => applenotes::convert(data, &filename),
        "gpg"            => gpg::convert(data, &filename),
        "rar"            => rar::convert(data, &filename),
        "zip"            => zip::convert(data, &filename),
        "bks"            => bks::convert(data, &filename),
        "ccache"         => ccache::convert(data, &filename),
        "ejabberd"       => ejabberd::convert(data, &filename),
        "gitea"          => gitea::convert(data, &filename),
        "ikescan"        => ikescan::convert(data, &filename),
        "kdcdump"        => kdcdump::convert(data, &filename),
        "keystore"       => keystore_jks::convert(data, &filename),
        "keplr"          => keplr::convert(data, &filename),
        "kirbi"          => kirbi::convert(data, &filename),
        "krb"            => krb::convert(data, &filename),
        "kwallet"        => kwallet::convert(data, &filename),
        "lotus"          => lotus::convert(data, &filename),
        "prosody"        => prosody::convert(data, &filename),
        "radius"         => radius::convert(data, &filename),
        "sipdump"        => sipdump::convert(data, &filename),
        _ => None,
    }
}

/// Converters that positively identify their input — a magic number, a checksum
/// or a structure strict enough that a false match is implausible.
///
/// Only these are tried during the blind "unknown type, try everything" sweep.
/// Converters outside this set can still be selected explicitly by name; they
/// are excluded because they key off loose textual cues (a colon, a "::", a
/// plausible length) and will happily claim an unrelated file. That is how a
/// plain text file used to be reported as a Telegram hash.
pub fn fallback_safe(name: &str) -> bool {
    matches!(
        name,
        "7z" | "ansible"
            | "androidbackup"
            | "axcrypt"
            | "bitcoin"
            | "bitlocker"
            | "bks"
            | "ccache"
            | "dmg"
            | "electrum"
            | "encfs"
            | "ethereum"
            | "gpg"
            | "keepass"
            | "keystore"
            | "kirbi"
            | "known_hosts"
            | "luks"
            | "mozilla"
            | "office"
            | "openssl"
            | "pcap"
            | "pdf"
            | "pem"
            | "pgpdisk"
            | "pgpsda"
            | "pgpwde"
            | "pwsafe"
            | "rar"
            | "ssh"
            | "telegram"
            | "zed"
            | "zip"
    )
}

/// Returns all known converter names.
pub fn all_names() -> &'static [&'static str] {
    &[
        "ansible", "atmail", "bitcoin", "bitlocker", "bitwarden", "blockchain",
        "cisco", "dmg", "electrum", "encfs", "ethereum", "ios", "keepass",
        "lastpass", "ldif", "lion", "luks", "mac", "mongodb", "mozilla",
        "netntlm", "network", "office", "1password", "pcap", "pdf", "pgpdisk",
        "pgpsda", "pgpwde", "pwsafe", "sap", "7z", "signal", "ssh", "telegram",
        "truecrypt", "vdi", "veracrypt", "zed",
        "androidbackup", "androidfde", "axcrypt", "bestcrypt", "cardano",
        "coinomi", "dashlane", "deepsound", "diskcryptor", "dpapimk", "ecryptfs",
        "enpass", "fvde", "geli", "htdigest", "hccapx", "iwork", "keychain",
        "keyring", "known_hosts", "libreoffice", "monero", "multibit",
        "openbsd_softraid", "openssl", "pem", "pfx", "restic", "staroffice",
        "strip", "tezos", "vmx",
        "aix", "andotp", "applenotes", "bks", "ccache", "ejabberd", "gitea",
        "ikescan", "kdcdump", "keystore", "keplr", "kirbi", "krb", "kwallet",
        "lotus", "prosody", "radius", "sipdump",
        "gpg", "rar", "zip",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write `data` to a unique temp file and return its path, so path-based
    /// converters (ios, mozilla, signal, 1password) are exercised on real bytes.
    fn temp_file(tag: &str, data: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("hashcatizer_fuzz_{}_{}", tag, data.len()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(data).unwrap();
        p
    }

    /// Run every converter against `data` (via the same path main.rs uses).
    /// A panic inside any convert() fails the test — that is the assertion.
    fn run_all(tag: &str, data: &[u8]) {
        let path = temp_file(tag, data);
        let path_str = path.to_string_lossy().to_string();
        for name in all_names() {
            let _ = run(name, data, &path_str);
        }
        let _ = std::fs::remove_file(&path);
    }

    // ---- Targeted regression tests for the verified truncation panics ----
    // Each previously aborted the process (panic = "abort"); now they must
    // return cleanly. We assert no panic and that no bogus hash is produced.

    fn assert_no_hash(name: &str, data: &[u8]) {
        let path = temp_file(name, data);
        let out = run(name, data, &path.to_string_lossy());
        let _ = std::fs::remove_file(&path);
        assert!(
            out.as_ref().is_none_or(|v| v.is_empty()),
            "{} unexpectedly produced output on truncated input: {:?}",
            name, out
        );
    }

    #[test]
    fn axcrypt_truncated_does_not_panic() {
        // magic + 7 bytes: loop entered with <8 bytes left for the 2nd u32.
        assert_no_hash("axcrypt", b"\xc0\xb9\x07\x2e\x00\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    fn zed_truncated_does_not_panic() {
        // 16-byte delimiter + 2 bytes: global_iv slice ran 16 bytes past EOF.
        assert_no_hash(
            "zed",
            b"\x07\x65\x92\x1A\x2A\x07\x74\x53\x47\x52\x07\x33\x61\x71\x93\x00\xAA\xBB",
        );
    }

    #[test]
    fn keepass_truncated_does_not_panic() {
        // KDBX4 sig + version(major=4) + 1 field_id byte, then EOF.
        assert_no_hash(
            "keepass",
            b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x00\x04\x04\x00\x01",
        );
    }

    #[test]
    fn pgpdisk_truncated_does_not_panic() {
        // "dPGP"+"MAIN" record (u32_le magic 0x50475064 / type 0x4E49414D),
        // then 52 bytes — salt slice [60..76] ran past a 60-byte file.
        let mut d = b"dPGPMAIN".to_vec();
        d.extend(std::iter::repeat_n(0u8, 52));
        assert_no_hash("pgpdisk", &d);
    }

    #[test]
    fn office_filepass_truncated_does_not_panic() {
        // OLE2 sig + FilePass opcode + short major=1 record (<58 bytes).
        let mut d = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec();
        d.extend_from_slice(b"\x2f\x00\x00\x00\x01\x00\x00\x00\x00\x00");
        assert_no_hash("office", &d);
    }

    #[test]
    fn mac_sha512_truncated_does_not_panic() {
        // bplist + SALTED-SHA512 marker + 0x44 data tag + <68 bytes.
        let mut d = b"bplist00SALTED-SHA512".to_vec();
        d.extend_from_slice(b"\x44\x01\x02\x03");
        assert_no_hash("mac", &d);
    }

    #[test]
    fn sevenz_truncated_header_does_not_panic() {
        let mut d = b"7z\xbc\xaf\x27\x1c".to_vec();
        d.extend(std::iter::repeat_n(0u8, 26));
        assert_no_hash("7z", &d);
    }

    #[test]
    fn pcap_short_ntlm_does_not_panic() {
        let mut d = b"\xa1\xb2\xc3\xd4NTLMSSP\x00\x03\x00\x00\x00".to_vec();
        d.extend(std::iter::repeat_n(0u8, 80));
        let _ = run("pcap", &d, "x.pcap"); // just must not panic
    }

    /// A converter is only allowed in the blind auto-detect sweep if it can
    /// actually recognise its own format. This asserts that directly: feed each
    /// allowlisted converter obvious non-matches and require silence.
    ///
    /// Without this guard the sweep reports whatever the first permissive
    /// converter says, which is how a plain text file came back as a Telegram
    /// hash and a PEM certificate as a VirtualBox disk.
    #[test]
    fn fallback_safe_converters_reject_unrelated_input() {
        let text = "lorem ipsum dolor sit amet\n".repeat(200);
        let toml = "[package]\nname = \"x\"\nversion = \"1.0\"\n".repeat(40);
        let cpp = "std::vector<int> v;\nfoo::bar::baz\n".repeat(40);
        let pseudo_random: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();

        let decoys: &[(&str, &[u8])] = &[
            ("zeros", &[0u8; 8192]),
            ("ones", &[0xffu8; 8192]),
            ("text", text.as_bytes()),
            ("toml", toml.as_bytes()),
            ("cpp", cpp.as_bytes()),
            ("pseudo_random", &pseudo_random),
        ];

        for name in all_names() {
            if !fallback_safe(name) {
                continue;
            }
            for (label, bytes) in decoys {
                let path = temp_file(&format!("decoy_{}_{}", name, label), bytes);
                let got = run(name, bytes, &path.to_string_lossy());
                let _ = std::fs::remove_file(&path);
                assert!(
                    got.as_ref().is_none_or(|v| v.is_empty()),
                    "converter '{}' is marked fallback_safe but matched {} input: {:?}\n\
                     Either tighten its format check or drop it from fallback_safe().",
                    name,
                    label,
                    got
                );
            }
        }
    }


    /// BestCrypt round-trip against John the Ripper's own test vectors.
    ///
    /// Each string in `bestcrypt_fmt_plug.c` was produced from a real
    /// container, so rebuilding the DATA_BLOCK from its fields and
    /// re-extracting proves the parser reads the offsets JtR wrote from —
    /// the closest thing to a reference container available without the
    /// commercial product. Covers all three hash types.
    #[test]
    fn bestcrypt_roundtrips_jtr_test_vectors() {
        const VECTORS: &[&str] = &[
        "$BestCrypt$1$5$3$16384$240$3154116612$128$32$51f7450dccbb1c947dd46138bf0d80d588b6938b02505642dde9e1ea61481485$1$a186f281fbbc68f3b27c7b4cc16b7916a2e19c2695b34ee4133a6ac6373db67b88fb54e3def1c0d288d3170dcb5860c2f190ab199fde7f1072a2a109441e608ae46890c5f18ab80803012a43d9cc595a45c5b9ed8b3ed3330cab1a29e5a96512e2f2e0e5927d6836c3a67c1cd13a61a8201a0a99be84c3e19e6d8a12330ae72c22179d37bb7d55034bb96b5cf9f73c11fa82be31d06bfe33305b616cc72079777a5f1f4a720b56470a83da08c17cbc86e34961c4f0bdb8556e2afa0b2b890780e03304725ce7cf8c592f037beb04b393f4f02e3bc9f6582082a39d31f2e643c5f7811f30eeee2ccc6c11496b7d70dc0d300e145408d28448ff5d929c42007dbe",
        "$BestCrypt$1$5$3$16384$240$3154116612$10$64$7f36390c85bc5695d49d5d135cb09e00cbf738bb203d0f0a0181805acc15d1cc6f856af0f738c44eead724a854700700a1595b5b30d47242a277b60df6491dde$1$a5b6a69b5cb04be789b42e1f50d3426048ea0df06c3b9a9932d85bd54b99aae202c1ca2e283786a4154f09fa01014ecab7f95c3b9a9b6adab1a695153ca8bffec2408566a7da986c0f107c57404c96823bbdc18a4b11337d211b49d7a133cf951b03c54aaccf3ed9b6445e472ba508add524fb67343e954efe313f544d8ecd6f99e9731fa147c62e17a07954f4a265b43cad4247d61529a3e8760d91c5a4314238eb78e10c2521309b7b827be302a32ee37e03854a8c4f872a07fac709b6170f2e7bd9d723f65ba3fd3766c42ed4a4f8dcc55e4c3b9d4e1dcf2bc54a23a87763f4379afdd9d8e934f254f713f3ba80369f26de2c5195c5e04405acdb2893990a",
        "$BestCrypt$1$5$3$16384$240$3154116612$129$64$06b513b2ac314636f616747c4171700133c00d335ee6a6c3a8db60bf672531624f099fa90b8047a5aceb2492c5858cab529cf9ba5d7e8c715e33517b64ef4251$1$5fc5bf3251a22f40cd23bf7a2bed453915f9037d80630d50c4c1d9d5ed3380fbf495e3013a2f1ada864afb2d4cdcc8dcaa8f86be5898bad53244d4382a42ba857420cff29b85c644c43305e9d0daf70a8db9dcaa0acc2d6b7c7e16374c30936a7d457a155ad5f6427c2818b85065eb6ab3751f91d8321ccdbfd13df038a26a01dbee887db43564588a7387e001ec5d23b22cb003a814ebb7cb4cec9b4cfd93e15bdedff0dd6dbbfff6e7fb3abf5f29ce891e3e432795600ea447c95a0900bd48d5ecc18fd6191b34dffe411412e8e8a8a8840d95cf77a51fb58248fbf940429a977f6f392cf6d1fe7b1ead0ee7ccc5264725c476b3f1fe087ffb8d811b6b2a8b",
        ];

        for expected in VECTORS {
            let f: Vec<&str> = expected.split('$').collect();
            let (keygen, wver): (u16, u16) = (f[3].parse().unwrap(), f[4].parse().unwrap());
            let iterations: u32 = f[5].parse().unwrap();
            let (alg, mode, hash_id): (u32, u32, u32) = (
                f[6].parse().unwrap(),
                f[7].parse().unwrap(),
                f[8].parse().unwrap(),
            );
            let salt = hex::decode(f[10]).unwrap();
            let key = hex::decode(f[12]).unwrap();

            // Lay the fields back out at their DATA_BLOCK offsets.
            let mut blk = vec![0u8; 1536 + 2560];
            blk[3..11].copy_from_slice(b"LOCOS94 ");
            blk[43..54].copy_from_slice(b"BC_KeyGenID");
            blk[54..56].copy_from_slice(&keygen.to_le_bytes());
            blk[56..58].copy_from_slice(&wver.to_le_bytes());
            blk[58..62].copy_from_slice(&iterations.to_le_bytes());
            blk[128..132].copy_from_slice(&alg.to_le_bytes());
            blk[132..136].copy_from_slice(&mode.to_le_bytes());
            blk[136..140].copy_from_slice(&hash_id.to_le_bytes());
            // keymap: slot 0 holds the salt, slot 1 an active key.
            blk[142..144].copy_from_slice(&5i16.to_le_bytes());
            blk[150..152].copy_from_slice(&1i16.to_le_bytes());
            blk[1536..1536 + salt.len()].copy_from_slice(&salt);
            blk[1536 + 256..1536 + 256 + key.len()].copy_from_slice(&key);

            let got = run("bestcrypt", &blk, "vector.jbc");
            assert_eq!(
                got.as_ref().and_then(|v| v.first()).map(String::as_str),
                Some(*expected),
                "bestcrypt did not round-trip JtR vector (hash_id {})",
                hash_id
            );
        }
    }

    // ---- Generic sweep: no converter may panic on malformed input ----

    #[test]
    fn no_converter_panics_on_malformed_input() {
        // Seeds = format magic bytes / structural prefixes that steer each
        // converter into its deep parse path. Truncating at every length and
        // padding with zeros surfaces off-by-N slice/offset panics.
        let seeds: &[&[u8]] = &[
            b"\xc0\xb9\x07\x2e",                                     // axcrypt
            b"\x07\x65\x92\x1A\x2A\x07\x74\x53\x47\x52\x07\x33\x61\x71\x93\x00", // zed delim
            b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x00\x04\x04\x00",     // keepass kdbx4
            b"\x03\xd9\xa2\x9a",                                     // keepass kdb1
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x2f\x00",             // office OLE2 + FilePass
            b"7z\xbc\xaf\x27\x1c",                                   // 7z
            b"%PDF-1.7",                                             // pdf
            b"dPGPMAIN",                                             // pgpdisk
            b"PGPSDA",                                               // pgpsda
            b"RESUMMYS",                                             // pgpwde
            b"LUKS\xba\xbe",                                         // luks
            b"PWS3",                                                 // pwsafe
            b"\x03-FVE-FS-",                                         // bitlocker (sig at off 3)
            b"\xfe\xed\xfe\xed",                                     // keystore jks
            b"bplist00SALTED-SHA512-PBKDF2",                         // mac pbkdf2
            b"bplist00BackupKeyBag\x4f\x1f",                         // ios keybag ext-len
            b"\xa1\xb2\xc3\xd4NTLMSSP\x00\x03\x00\x00\x00",          // pcap ntlm
            b"encrcdsa\x00\x00\x00\x02",                             // dmg v2
            b"encrcdsa\x00\x00\x00\x01",                             // dmg v1
            b"Salted__",                                             // openssl_enc / 1password
            b"$ANSIBLE_VAULT;1.1;AES256",                            // ansible
            b"\x00\x00\x00\x02",                                     // bks magic
            b"PK\x03\x04",                                           // zip lfh
            b"PK\x03\x04\x33\x00\x01\x00\x63\x00",                   // zip winzip-aes-ish
            b"Rar!\x1a\x07\x00",                                     // rar3
            b"Rar!\x1a\x07\x00s\x80\x00",                            // rar3 -hp main hdr
            b"Rar!\x1a\x07\x01\x00",                                 // rar5
            b"Rar!\x1a\x07\x01\x00\x00\x00\x00\x00\x05\x04\x00",     // rar5 crypt block
            b"\x95\x01\x04",                                         // gpg old-format secret key
            b"\xc5\x04",                                             // gpg new-format secret key
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n=AAAA\n-----END", // gpg armored
        ];
        for (i, seed) in seeds.iter().enumerate() {
            for len in 0..=seed.len() {
                run_all(&format!("seed{}_t", i), &seed[..len]);
                // also pad with zeros past the magic to reach later parse steps
                let mut padded = seed[..len].to_vec();
                padded.extend(std::iter::repeat_n(0u8, 64));
                run_all(&format!("seed{}_p", i), &padded);
            }
        }
        // Pure-garbage buffers of assorted sizes.
        for len in [0usize, 1, 2, 3, 7, 15, 31, 63, 199, 511, 2047] {
            run_all("garbage", &vec![0xABu8; len]);
            run_all("ff", &vec![0xFFu8; len]);
        }
    }

    // ---- Positive round-trip tests for the new zip/rar/gpg converters ----
    // Inputs are constructed to match the adversarially-verified hashcat format
    // specs; expected outputs are exact.

    fn vint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 { out.push(b | 0x80); } else { out.push(b); break; }
        }
        out
    }

    #[test]
    fn zip_winzip_aes_extracts_expected() {
        let salt: Vec<u8> = (0u8..16).collect();
        let verify = [0x13u8, 0x20];
        let ct = b"\x19\x64\x8c\x3e\x06\x3c\x82\xa9\xad\x3e\xf0\x8e\xd8\x33"; // 14 bytes
        let auth = b"\x31\x35\xc7\x9e\xcb\x86\xcd\x6f\x48\xfc"; // 10 bytes
        let mut blob = salt.clone();
        blob.extend_from_slice(&verify);
        blob.extend_from_slice(ct);
        blob.extend_from_slice(auth);
        let comp_size = blob.len() as u32;
        let fname = b"a.txt";
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x9901u16.to_le_bytes());
        extra.extend_from_slice(&7u16.to_le_bytes());
        extra.extend_from_slice(&2u16.to_le_bytes()); // version
        extra.extend_from_slice(b"AE");               // vendor
        extra.push(3);                                // strength = AES-256
        extra.extend_from_slice(&8u16.to_le_bytes()); // real method
        let mut z = b"PK\x03\x04".to_vec();
        z.extend_from_slice(&51u16.to_le_bytes()); // version
        z.extend_from_slice(&1u16.to_le_bytes());  // flags
        z.extend_from_slice(&99u16.to_le_bytes()); // method
        z.extend_from_slice(&0u16.to_le_bytes());  // time
        z.extend_from_slice(&0u16.to_le_bytes());  // date
        z.extend_from_slice(&0u32.to_le_bytes());  // crc
        z.extend_from_slice(&comp_size.to_le_bytes());
        z.extend_from_slice(&0u32.to_le_bytes());  // uncompressed
        z.extend_from_slice(&(fname.len() as u16).to_le_bytes());
        z.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        z.extend_from_slice(fname);
        z.extend_from_slice(&extra);
        z.extend_from_slice(&blob);
        let out = run("zip", &z, "a.zip").unwrap();
        assert_eq!(
            out[0],
            "$zip2$*0*3*0*000102030405060708090a0b0c0d0e0f*1320*e*19648c3e063c82a9ad3ef08ed833*3135c79ecb86cd6f48fc*$/zip2$"
        );
    }

    #[test]
    fn rar3_hp_extracts_expected() {
        let mut r = b"Rar!\x1a\x07\x00".to_vec();
        // main header: crc(2) type=0x73 flags(2,0x0080) size(2) + padding
        r.extend_from_slice(&0u16.to_le_bytes());
        r.push(0x73);
        r.extend_from_slice(&0x0080u16.to_le_bytes());
        r.extend_from_slice(&13u16.to_le_bytes());
        r.extend(std::iter::repeat_n(0u8, 6 + 20));
        let salt = b"\x45\x10\x9a\xf8\xab\x5f\x29\x7a";
        let enc = b"\xad\xbf\x6c\x53\x85\xd7\xa4\x03\x73\xe8\xf7\x7d\x7b\x89\xd3\x17";
        r.extend_from_slice(salt);
        r.extend_from_slice(enc);
        let out = run("rar", &r, "a.rar").unwrap();
        assert_eq!(out[0], "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317");
    }

    #[test]
    fn rar5_crypt_extracts_expected() {
        let salt = b"\x74\x57\x55\x67\x51\x88\x07\x62\x22\x65\x58\x23\x27\x03\x22\x80";
        let iv = b"\xf8\xb4\x06\x4d\xe3\x4a\xc0\x2e\xca\xbf\xe9\xab\xdf\x93\xed\x6a";
        let pswchk = b"\x98\x43\x83\x4e\xd0\xf7\xc7\x54";
        let lg2 = 15u8;
        // csum = SHA-256(pswcheck)[:4] — value isn't validated by our parser.
        let csum = [0u8; 4];
        let mut crypt = vint(0);           // version
        crypt.extend(vint(1));             // flags (pswcheck)
        crypt.push(lg2);
        crypt.extend_from_slice(salt);
        crypt.extend_from_slice(pswchk);
        crypt.extend_from_slice(&csum);
        crypt.extend_from_slice(iv);
        let mut from_type = vint(0x04); // HeaderType
        from_type.extend(vint(0));      // HeaderFlags
        from_type.extend_from_slice(&crypt);
        let mut block = 0u32.to_le_bytes().to_vec(); // HeadCRC32
        block.extend(vint(from_type.len() as u64));  // HeaderSize
        block.extend_from_slice(&from_type);
        let mut r = b"Rar!\x1a\x07\x01\x00".to_vec();
        r.extend_from_slice(&block);
        let out = run("rar", &r, "a.rar").unwrap();
        assert_eq!(
            out[0],
            "$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754"
        );
    }

    #[test]
    fn gpg_secret_key_matches_hashcat_reference() {
        // Reconstruct the OpenPGP packet that yields hashcat's mode-17010 ST_HASH.
        let data_hex = "8833fa3812b5500aa9eb7e46febfa31a0584b7e4a5b13c198f5c9b0814243895cce45ac3714e79692fb5a130a1c943b9130315ce303cb7e6831be68ce427892858f313fc29f533434dbe0ef26573f2071bbcc1499dc49bda90648221ef3823757e2fba6099a18c0c83386b21d8c9b522ec935ecd540210dbf0f21c859429fd4d35fa056415d8087f27b3e66b16081ea18c544d8b2ea414484f17097bc83b773d92743f76eb2ccb4df8ba5f5ff84a5474a5e8a8e5179a5b0908503c55e428de04b40628325739874e1b4aa004c4cbdf09b0b620990a8479f1c9b4187e33e63fe48a565bc1264bbf4062559631bef9e346a7217f1cabe101a38ac4be9fa94f6dafe6b0301e67792ed51bca04140cddd5cb6e80ac6e95e9a09378c9651588fe360954b622c258a3897f11246c944a588822cc6daf1cb81ccc95098c3bea8432f1ee0c663b193a7c7f1cdfeb91eee0195296bf4783025655cbebd7c70236";
        let iv = "a47ef38987beab0a0b9bfe74b72822e8";
        let salt = "1f5c90d9820997db";
        let encdata = hex::decode(data_hex).unwrap();
        let mut body = vec![4u8];                 // version
        body.extend_from_slice(&[0x5a, 0, 0, 0]); // creation time
        body.push(1);                             // RSA
        body.extend_from_slice(&1024u16.to_be_bytes()); // MPI n bitlen
        body.extend(std::iter::repeat_n(0u8, 128));
        body.extend_from_slice(&17u16.to_be_bytes());   // MPI e bitlen
        body.extend_from_slice(&[0x01, 0x00, 0x01]);
        body.push(254); // usage
        body.push(7);   // AES-128
        body.push(3);   // S2K iterated+salted
        body.push(2);   // SHA-1
        body.extend_from_slice(&hex::decode(salt).unwrap());
        body.push(0x60); // coded count -> 65536
        body.extend_from_slice(&hex::decode(iv).unwrap());
        body.extend_from_slice(&encdata);
        let mut pkt = vec![0x95u8]; // old-format, tag 5, 2-byte length
        pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&body);
        let out = run("gpg", &pkt, "secring.gpg").unwrap();
        let expected = format!(
            "$gpg$*1*348*1024*{}*3*254*2*7*16*{}*65536*{}",
            data_hex, iv, salt
        );
        assert_eq!(out[0], expected);
    }

    #[test]
    fn text_converters_handle_multibyte_utf8() {
        // Text converters slice &str at byte offsets; a multibyte char straddling
        // a fixed cut used to panic. The euro sign (3 bytes) probes those cuts.
        let e = "\u{20ac}"; // €
        let lines: Vec<String> = vec![
            format!("password 7 1{}56", e),                    // cisco type-7 decode
            format!("password 5 $1${}$x", e),                  // cisco type-5 passthrough
            format!("a:1:{}{}", "0".repeat(63), e),            // lastpass hash field
            format!("user:{}", e.repeat(40)),                  // atmail / lion-ish
            format!("{}:{}:{}", e, e, e),                       // generic colon-delimited
            format!("dn: uid={}\nuserpassword: {}", e, e),     // ldif
            format!("userpassword:: {}", e),                   // ldif base64 path
            format!("enable secret ${}", e),                   // cisco enable
        ];
        for (i, line) in lines.iter().enumerate() {
            run_all(&format!("utf8_{}", i), line.as_bytes());
        }
    }

    #[test]
    fn macos_sha512_emits_the_m1722_layout() {
        // hashcat -m 1722 takes an 8 hex char salt and a 128 hex char digest
        // concatenated with no separator. Both converters used to wrap those in
        // "$ml$0$<salt>$<digest>", which is the shape of -m 7100 -- but 7100 is
        // the 10.8+ PBKDF2 format and needs a real iteration count, so a zero
        // there matched no mode and the output could not be cracked at all.
        //
        // This vector is hashcat's own module_01722 example hash, password
        // "hashcat", and it cracks under -m 1722 exactly as emitted here.
        let vector = "07543781b07e905f6f947db8ae305c248b9e12f509b41097e852e2f450e8247\
90e677ea7397b8a9a552b1c19ecf6a6e1dd3844fa5ee5db23976962859676f7d2fb85ca94";
        let vector: String = vector.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(vector.len(), 136);

        let input = format!("alice:{}\n", vector);
        let out = super::lion::convert(input.as_bytes(), "shadow").expect("lion should parse");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0], format!("alice:{}", vector));
        assert!(!out[0].contains("$ml$"), "must not emit the -m 7100 shape");
    }
}
