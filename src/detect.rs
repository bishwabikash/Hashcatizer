use std::path::Path;

/// Auto-detects file type from magic bytes, extension, and content.
/// Returns a converter name (e.g. "ssh", "keepass", "pdf") or None.
pub fn detect_file_type(path: &Path) -> Option<&'static str> {
    if path.is_dir() {
        // iOS backup directory
        if path.join("Manifest.plist").exists() {
            return Some("ios");
        }
        let name = path.to_string_lossy().to_lowercase();
        if name.ends_with(".agilekeychain") || name.ends_with(".opvault") {
            return Some("1password");
        }
        return None;
    }

    let data = match std::fs::read(path) {
        Ok(d) if !d.is_empty() => d,
        _ => return None,
    };
    // Only first 8 KB for inspection
    let head = &data[..data.len().min(8192)];

    // 1. Magic bytes
    if let Some(c) = detect_by_magic(head, &data) {
        return Some(c);
    }

    // 2. Extension
    let basename = path
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if let Some(c) = detect_by_extension(&ext, &basename) {
        return Some(c);
    }

    // 3. Content
    detect_by_content(head, &basename)
}

fn detect_by_magic(head: &[u8], full: &[u8]) -> Option<&'static str> {
    macro_rules! check {
        ($off:expr, $magic:expr, $name:expr) => {
            if head.len() >= $off + $magic.len() && &head[$off..$off + $magic.len()] == $magic {
                return Some($name);
            }
        };
    }
    check!(0, b"7z\xbc\xaf\x27\x1c", "7z");
    check!(0, b"%PDF", "pdf");
    check!(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office");
    // KeePass 2.x (longer magic first)
    if head.len() >= 8 && &head[0..8] == b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" {
        return Some("keepass");
    }
    check!(0, b"\x03\xd9\xa2\x9a", "keepass");
    check!(3, b"-FVE-FS-", "bitlocker");
    check!(0, b"LUKS\xba\xbe", "luks");
    check!(0, b"PWS3", "pwsafe");
    check!(0, b"\xa1\xb2\xc3\xd4", "pcap");
    check!(0, b"\xd4\xc3\xb2\xa1", "pcap");
    check!(0, b"\x0a\x0d\x0d\x0a", "pcap");
    check!(0, b"<<< ", "vdi");
    check!(0, b"bplist00", "mac");
    // RAR5 magic is a superset of RAR3's, so check the longer one first.
    check!(0, b"Rar!\x1a\x07\x01\x00", "rar");
    check!(0, b"Rar!\x1a\x07\x00", "rar");
    // GPG/OpenPGP binary keyring: secret-key packet (old-format tag 5 = 0x95,
    // new-format tag 5 = 0xc5). Only treat as gpg if an S2K-protected key parses.
    if (head.first() == Some(&0x95) || head.first() == Some(&0xc5))
        && crate::converters::gpg::convert(full, "").is_some()
    {
        return Some("gpg");
    }
    // DMG koly trailer
    if full.len() > 512 && &full[full.len() - 512..full.len() - 508] == b"koly" {
        return Some("dmg");
    }
    None
}

fn detect_by_extension(ext: &str, basename: &str) -> Option<&'static str> {
    match ext {
        "pdf" => Some("pdf"),
        "doc" | "xls" | "ppt" | "docx" | "xlsx" | "pptx" => Some("office"),
        "7z" => Some("7z"),
        "kdbx" | "kdb" => Some("keepass"),
        "psafe3" => Some("pwsafe"),
        "tc" => Some("truecrypt"),
        "hc" => Some("veracrypt"),
        "dmg" => Some("dmg"),
        "vdi" => Some("vdi"),
        "pcap" | "pcapng" | "cap" => Some("pcap"),
        "pgd" => Some("pgpdisk"),
        "sda" => Some("pgpsda"),
        "rar" => Some("rar"),
        "gpg" | "pgp" | "asc" => Some("gpg"),
        "axx" | "zed" => Some("zed"),
        "ldif" | "ldf" => Some("ldif"),
        "electrum" => Some("electrum"),
        "bitwarden" => Some("bitwarden"),
        "pem" => None, // need content
        "key" => None,
        _ if basename.ends_with(".encfs6.xml") => Some("encfs"),
        _ => None,
    }
}

fn detect_by_content(head: &[u8], basename: &str) -> Option<&'static str> {
    // PKCS#8 is its own format with its own hashcat modes (24410/24420), so it
    // must be checked before the generic "PRIVATE KEY" cue below claims it.
    if contains_prefix(head, b"-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Some("pem");
    }

    // SSH private keys
    if contains_prefix(head, b"-----BEGIN OPENSSH PRIVATE KEY-----")
        || contains_prefix(head, b"-----BEGIN RSA PRIVATE KEY-----")
        || contains_prefix(head, b"-----BEGIN DSA PRIVATE KEY-----")
        || contains_prefix(head, b"-----BEGIN EC PRIVATE KEY-----")
    {
        return Some("ssh");
    }
    if head.len() >= 512
        && head[..512].windows(16).any(|w| w == b"PRIVATE KEY-----") {
            return Some("ssh");
        }

    // GPG/OpenPGP armored private key
    if contains_prefix(head, b"-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return Some("gpg");
    }

    // Ansible Vault
    if head.starts_with(b"$ANSIBLE_VAULT") {
        return Some("ansible");
    }

    // WinZip AES-encrypted ZIP. ZIP also backs ODF (libreoffice) / iWork / docx,
    // so only claim "zip" when the AES extra-field id 0x9901 is present and the
    // ODF/iWork document markers are not.
    if head.starts_with(b"PK\x03\x04")
        && !contains(head, b"META-INF/manifest.xml")
        && !contains(head, b"EncryptedDocument")
        && contains(head, b"\x01\x99")
    {
        return Some("zip");
    }

    // EncFS XML
    if contains(head, b"<boost_serialization") && contains_ci(head, b"encfs") {
        return Some("encfs");
    }
    if basename == ".encfs6.xml" || basename == "encfs6.xml" {
        return Some("encfs");
    }

    // iOS backup manifest
    if basename == "manifest.plist" || contains(head, b"BackupKeyBag") {
        return Some("ios");
    }

    // Mozilla key databases
    if basename == "key4.db" || basename == "key3.db" || basename == "cert9.db" {
        return Some("mozilla");
    }
    if head.starts_with(b"SQLite format 3\x00") {
        if basename.starts_with("key") && (basename.ends_with(".db")) {
            return Some("mozilla");
        }
        if basename.contains("signal") {
            return Some("signal");
        }
    }

    // Cisco config text
    let text = std::str::from_utf8(head).unwrap_or("");
    for pat in &["enable secret", "password 5 $", "password 7 ", "password 8 $", "password 9 $"] {
        if text.contains(pat) {
            return Some("cisco");
        }
    }

    // LDIF
    let ltxt = text.trim_start();
    if ltxt.starts_with("dn:") || text.contains("userPassword") {
        return Some("ldif");
    }

    // JSON-based detection
    if head.first() == Some(&b'{') || head.first() == Some(&b'[') {
        if let Ok(j) = serde_json::from_slice::<serde_json::Value>(head) {
            let obj = j.as_object();
            if let Some(o) = obj {
                if o.contains_key("crypto") || o.contains_key("Crypto") || o.contains_key("keystore") {
                    return Some("ethereum");
                }
                if o.contains_key("wallet_type") {
                    return Some("electrum");
                }
                if o.contains_key("SL5") || o.contains_key("keysets") {
                    return Some("1password");
                }
                if o.contains_key("payload") && o.contains_key("pbkdf2_iterations") {
                    return Some("blockchain");
                }
                if let Some(creds) = o.get("credentials") {
                    if creds.get("SCRAM-SHA-1").is_some() || creds.get("SCRAM-SHA-256").is_some() {
                        return Some("mongodb");
                    }
                }
                if o.contains_key("iterations") && o.contains_key("username") {
                    return Some("lastpass");
                }
                if o.contains_key("encryptedKey") || o.contains_key("encKey") {
                    return Some("bitwarden");
                }
            }
        }
    }

    // Bitcoin wallet.dat
    if (contains(head, b"\x00\x06\x15\x61") || contains_ci(head, b"bitcoin"))
        && (basename == "wallet.dat" || contains(head, b"\x62\x31\x05\x00\x09\x00"))
    {
        return Some("bitcoin");
    }

    // NetNTLM. Validate an actual line rather than the mere presence of "::",
    // which also matches C++ scope resolution, IPv6 literals and YAML.
    if text
        .lines()
        .any(|l| crate::converters::netntlm::classify(l.trim()).is_some())
    {
        return Some("netntlm");
    }

    // PGP SDA
    if contains(head, b"PGPSDA") {
        return Some("pgpsda");
    }

    // ZED container
    if contains(head, b"\x07\x65\x92\x1A\x2A\x07\x74\x53") {
        return Some("zed");
    }

    // PGP Disk
    if contains(head, b"PGPd") || contains(head, b"dPGP") {
        return Some("pgpdisk");
    }

    // PGP WDE
    if contains(head, b"RESU") && contains(head, b"MMYS") {
        return Some("pgpwde");
    }

    None
}

// ---------- small helpers ----------
fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}
fn contains_ci(data: &[u8], needle: &[u8]) -> bool {
    // case-insensitive ASCII search
    let n: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    data.windows(n.len())
        .any(|w| w.iter().zip(n.iter()).all(|(a, b)| a.to_ascii_lowercase() == *b))
}
fn contains_prefix(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Hash-string identification
// ---------------------------------------------------------------------------

/// Identifies an already-formatted hash string.
/// Returns a list of (name, mode) matches.
pub fn identify_hash(hash: &str) -> Vec<(&'static str, u32)> {
    let mut results = Vec::new();

    macro_rules! try_prefix {
        ($prefix:expr, $name:expr, $mode:expr) => {
            if hash.starts_with($prefix) {
                results.push(($name, $mode));
            }
        };
    }
    macro_rules! try_regex {
        ($pat:expr, $name:expr, $mode:expr) => {
            if {
                use once_cell::sync::Lazy;
                use regex::Regex;
                static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pat).unwrap());
                RE.is_match(hash)
            } {
                results.push(($name, $mode));
            }
        };
    }

    try_prefix!("$1$", "md5crypt", 500);
    try_prefix!("$apr1$", "Apache APR1", 1600);
    try_prefix!("$2a$", "bcrypt", 3200);
    try_prefix!("$2b$", "bcrypt", 3200);
    try_prefix!("$2y$", "bcrypt", 3200);
    try_prefix!("$5$", "sha256crypt", 7400);
    try_prefix!("$6$", "sha512crypt", 1800);
    try_prefix!("$7z$", "7-Zip", 11600);
    try_prefix!("$keepass$", "KeePass", 13400);
    try_prefix!("$office$*2013*", "MS Office 2013+", 9600);
    try_prefix!("$office$*2010*", "MS Office 2010", 9500);
    try_prefix!("$office$*2007*", "MS Office 2007", 9400);
    try_prefix!("$oldoffice$", "MS Office <= 2003", 9700);
    try_prefix!("$pdf$", "PDF", 10400);
    try_prefix!("$sshng$", "SSH", 22911);
    try_prefix!("$ethereum$", "Ethereum Wallet", 15600);
    try_prefix!("$bitlocker$", "BitLocker", 22100);
    try_prefix!("$luks$", "LUKS", 14600);
    try_prefix!("$minecraft$", "Minecraft", 8900);
    try_prefix!("$ansible$", "Ansible Vault", 16900);
    try_prefix!("$krb5pa$", "Kerberos 5 Pre-Auth", 7500);
    try_prefix!("$krb5tgs$", "Kerberos 5 TGS-REP", 13100);
    try_prefix!("$krb5asrep$", "Kerberos 5 AS-REP", 18200);
    try_prefix!("$8$", "Cisco Type 8", 9200);
    try_prefix!("$9$", "Cisco Type 9", 9300);
    try_prefix!("$bitcoin$", "Bitcoin wallet", 11300);
    try_prefix!("$pwsafe$", "Password Safe v3", 5200);
    try_prefix!("$blockchain$", "Blockchain wallet", 12700);
    try_prefix!("$cloudkeychain$", "1Password cloudkeychain", 8200);
    try_prefix!("$agilekeychain$", "1Password agilekeychain", 6600);
    try_prefix!("$bitwarden$", "Bitwarden", 31700);
    try_prefix!("$dmg$", "Apple DMG", 6211);
    try_prefix!("$encfs$", "EncFS", 26401);
    try_prefix!("$lastpass$", "LastPass", 6800);
    try_prefix!("$pgpsda$", "PGP SDA", 10900);
    try_prefix!("$pgpdisk$", "PGP Disk", 17010);
    try_prefix!("$pgpwde$", "PGP WDE", 17010);
    try_prefix!("$ml$", "macOS PBKDF2-SHA512", 7100);
    try_prefix!("$itunes_backup$", "iTunes Backup", 14700);
    try_prefix!("$keepass$", "KeePass", 13400);
    try_prefix!("$signal$", "Signal Desktop", 28200);
    try_prefix!("$telegram$", "Telegram Desktop", 24500);
    try_prefix!("$electrum$", "Electrum", 16600);
    try_prefix!("$mozilla$", "Mozilla key3/key4", 26100);
    try_prefix!("$vbox$", "VirtualBox", 27000);
    try_prefix!("$zed$", "ZED/AxCrypt", 0);
    try_prefix!("$ab$", "Android Backup", 18900);
    try_prefix!("$monero$", "Monero Wallet", 28300);
    try_prefix!("$dashlane$", "Dashlane", 28000);
    try_prefix!("$tezos$", "Tezos Wallet", 25900);
    try_prefix!("$restic$", "Restic", 0);
    try_prefix!("$openssl$", "OpenSSL enc", 15400);
    try_prefix!("$ecryptfs$", "eCryptfs", 12200);
    try_prefix!("$keychain$", "macOS Keychain", 23100);
    try_prefix!("$keyring$", "GNOME Keyring", 23200);
    try_prefix!("$enpass$", "Enpass", 0);
    try_prefix!("$axcrypt$", "AxCrypt", 13200);
    try_prefix!("$iwork$", "Apple iWork", 23400);
    try_prefix!("$odf$", "LibreOffice/ODF", 18400);
    try_prefix!("$pfx$", "PFX/PKCS#12", 23700);
    try_prefix!("$geli$", "FreeBSD GELI", 26500);
    try_prefix!("$PEM$", "PEM private key", 22911);
    try_prefix!("$vmx$", "VMware VMX", 27400);
    try_prefix!("$sip$", "SIP digest", 11400);
    try_prefix!("$ANP$", "Apple Notes", 0);
    try_prefix!("$scram$", "SCRAM challenge", 0);
    try_prefix!("$fvde$", "Mac FileVault 2", 16700);
    try_prefix!("$zip2$", "WinZip AES", 13600);
    try_prefix!("$RAR3$*0*", "RAR3 (-hp encrypted headers)", 12500);
    try_prefix!("$RAR3$*1*", "RAR3 (-p encrypted data)", 23700);
    try_prefix!("$rar5$", "RAR5", 13000);
    try_prefix!("$gpg$", "GPG/OpenPGP secret key", 17010);

    // Bare hex hashes
    try_regex!(r"^[a-fA-F0-9]{32}$", "MD5 / NTLM", 0);
    try_regex!(r"^[a-fA-F0-9]{40}$", "SHA-1", 100);
    try_regex!(r"^[a-fA-F0-9]{64}$", "SHA-256", 1400);
    try_regex!(r"^[a-fA-F0-9]{128}$", "SHA-512", 1700);
    try_regex!(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", "LM:NTLM", 1000);
    try_regex!(
        r"^[^:]+::[^:]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+$",
        "NetNTLMv2",
        5600
    );

    results
}

/// Returns true if the string looks more like a hash than a filename.
#[allow(dead_code)]
pub fn is_hash_string(s: &str) -> bool {
    // All hex
    if s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Starts with common hash prefixes
    for prefix in &[
        "$1$", "$2a$", "$2b$", "$2y$", "$5$", "$6$", "$apr1$",
        "$7z$", "$keepass$", "$office$", "$pdf$", "$sshng$",
        "$ethereum$", "$bitlocker$", "$luks$", "$ansible$",
        "$krb5", "$8$", "$9$", "$bitcoin$", "$pwsafe$",
        "$blockchain$", "$pgp", "$ml$", "$dmg$", "$encfs$",
        "$signal$", "$telegram$", "$electrum$", "$mozilla$",
    ] {
        if s.starts_with(prefix) {
            return true;
        }
    }
    // NetNTLM :: pattern
    if s.contains("::") && s.contains(':') {
        return true;
    }
    false
}
