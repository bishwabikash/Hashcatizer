use std::path::Path;
use std::process;

mod common;
mod der;
mod detect;
mod protobuf;
mod zipfile;
mod converters;

// Hashcat mode hints, verified against `hashcat --example-hashes` (v7.1.2).
//
// Entries are only listed when hashcat genuinely implements the format this
// converter emits. Several previous entries pointed at unrelated crackers
// (monero -> 26620 MetaMask, multibit -> 22200 Citrix NetScaler, bestcrypt ->
// 23400 Bitwarden, vdi -> 13711 VeraCrypt) or at modes that do not exist at
// all, which sends users to spend GPU hours on the wrong kernel. Formats john
// can crack but hashcat cannot are deliberately absent -- see `Crack::JohnOnly`.
fn hashcat_mode_hint(name: &str) -> Option<&'static str> {
    match name {
        // --- archives -------------------------------------------------------
        "7z"                => Some("11600"),
        "zip"               => Some("13600"),
        "rar"               => Some("12500/13000/23700"),
        "gpg"               => Some("17010/17020/17030/17040"),
        // --- disk containers ------------------------------------------------
        "bitlocker"         => Some("22100"),
        "truecrypt"         => Some("29311-29343"),
        "veracrypt"         => Some("29411-29483"),
        "diskcryptor"       => Some("20011/20012/20013"),
        "vdi"               => Some("27500/27600"),
        "luks"              => Some("14600/29511-29543"),
        "fvde"              => Some("16700"),
        "androidfde"        => Some("12900"),
        "ecryptfs"          => Some("12200"),
        // hashcat has no DMG kernel; this used to emit the TrueCrypt legacy
        // modes, which parse a completely different container and never crack.
        "dmg"               => None,
        // --- documents ------------------------------------------------------
        "pdf"               => Some("10400/10500/10600/10700"),
        "office"            => Some("9400/9500/9600/9700/9800"),
        "libreoffice"       => Some("18400"),
        "iwork"             => Some("23300"),
        // --- keys and keystores ---------------------------------------------
        "pem"               => Some("24410/24420"),
        "keystore"          => Some("15500"),
        // --- password managers ----------------------------------------------
        "keepass"           => Some("13400"),
        "lastpass"          => Some("6800"),
        "1password"         => Some("6600/8200"),
        "bitwarden"         => Some("23400"),
        "pwsafe"            => Some("5200"),
        "keychain"          => Some("23100"),
        "mozilla"           => Some("26000/26100"),
        // --- wallets --------------------------------------------------------
        "bitcoin"           => Some("11300"),
        "ethereum"          => Some("15600/15700"),
        "electrum"          => Some("16600/21700/21800"),
        "blockchain"        => Some("12700/15200/34700"),
        "multibit"          => Some("22500/27700"),
        // --- messaging / mobile ---------------------------------------------
        "androidbackup"     => Some("18900"),
        "ios"               => Some("14800"),
        "axcrypt"           => Some("13200"),
        // --- network / auth -------------------------------------------------
        "pcap"              => Some("22000/5500/5600"),
        "hccapx"            => Some("22000"),
        "ikescan"           => Some("5300/5400"),
        "sipdump"           => Some("11400"),
        "ejabberd"          => Some("23200"),
        "prosody"           => Some("23200"),
        "mongodb"           => Some("24100/24200"),
        "kirbi"             => Some("13100"),
        "krb"               => Some("7500/13100/18200/19600-19900"),
        "cisco"             => Some("500/9200/9300"),
        "sap"               => Some("7700/7800"),
        "mac"               => Some("7100"),
        "lion"              => Some("7100"),
        "dpapimk"           => Some("15300/15900"),
        "vmx"               => Some("27400"),
        "ansible"           => Some("16900"),
        _                   => None,
    }
}

/// Advice printed under the extracted hashes.
enum Crack {
    /// hashcat can crack this; the string is the -m argument.
    Hashcat(String),
    /// A real format, but no hashcat kernel exists for it.
    JohnOnly(&'static str),
    Unknown,
}

/// Prefer a mode derived from the hash itself over the converter's static
/// range: a converter can emit several formats, and only the emitted one is
/// actually crackable. Guessing here is what makes a tool waste someone's night
/// on the wrong -m.
fn crack_advice(name: &str, hashes: &[String]) -> Crack {
    if name == "ssh" {
        return match hashes.first().map(|h| converters::ssh::hashcat_mode(h)) {
            Some(Some(m)) => Crack::Hashcat(m.to_string()),
            Some(None) => Crack::JohnOnly(
                "OpenSSH bcrypt-pbkdf key — hashcat has no kernel for these; use john",
            ),
            None => Crack::Unknown,
        };
    }
    // Telegram Desktop spans three formats with three different modes; only the
    // emitted variant is meaningful.
    if name == "telegram" {
        if let Some(Some(m)) = hashes.first().map(|h| converters::telegram::hashcat_mode(h)) {
            return Crack::Hashcat(m.to_string());
        }
    }
    if name == "netntlm" {
        if let Some(Some(m)) = hashes.first().map(|h| converters::netntlm::classify(h)) {
            return Crack::Hashcat(m.to_string());
        }
    }
    match hashcat_mode_hint(name) {
        Some(m) => Crack::Hashcat(m.to_string()),
        None => Crack::Unknown,
    }
}

fn print_advice(name: &str, hashes: &[String]) {
    match crack_advice(name, hashes) {
        Crack::Hashcat(mode) => {
            eprintln!("[*] Crack with: hashcat -m {} <hashfile> <wordlist>", mode)
        }
        Crack::JohnOnly(why) => {
            eprintln!("[!] {}", why);
            eprintln!("[*] Crack with: john --wordlist=<wordlist> <hashfile>");
        }
        Crack::Unknown => {}
    }
}

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {} <file>                  Auto-detect and convert to hashcat format", prog);
    eprintln!("  {} <hash_string>           Identify hash type", prog);
    eprintln!("  {} <converter> <file>      Use explicit converter", prog);
    eprintln!("  {} --list                  List all supported converters", prog);
    eprintln!("  {} --help                  Show this help", prog);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("hashcatizer");

    if args.len() < 2 {
        print_usage(prog);
        process::exit(1);
    }

    match args[1].as_str() {
        "--help" | "-h" => {
            print_usage(prog);
            process::exit(0);
        }
        "--list" | "-l" => {
            println!("Supported converters:");
            for name in converters::all_names() {
                let hint = hashcat_mode_hint(name).map(|m| format!("  [hashcat -m {}]", m)).unwrap_or_default();
                println!("  {}{}", name, hint);
            }
            process::exit(0);
        }
        arg => {
            // Check if first arg is a known converter name
            if converters::all_names().contains(&arg) {
                // Explicit converter mode: hashcatizer <converter> <file>
                if args.len() < 3 {
                    eprintln!("Error: converter '{}' requires a file argument", arg);
                    process::exit(1);
                }
                let path = &args[2];
                run_converter(arg, path);
            } else if Path::new(arg).exists() {
                // File path: auto-detect and convert
                run_autodetect(arg);
            } else {
                // Treat as a hash string: identify type
                identify_hash_string(arg);
            }
        }
    }
}

fn run_converter(name: &str, path: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Error reading '{}': {}", path, e); process::exit(1); }
    };

    match converters::run(name, &data, path) {
        Some(hashes) if !hashes.is_empty() => {
            for h in &hashes {
                println!("{}", h);
            }
            print_advice(name, &hashes);
        }
        _ => {
            eprintln!("No hashes extracted from '{}' using converter '{}'", path, name);
            process::exit(1);
        }
    }
}

fn run_autodetect(path: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Error reading '{}': {}", path, e); process::exit(1); }
    };

    let converter_name = detect::detect_file_type(Path::new(path));

    match converter_name {
        Some(name) => {
            eprintln!("[*] Detected type: {}", name);
            match converters::run(name, &data, path) {
                Some(hashes) if !hashes.is_empty() => {
                    for h in &hashes {
                        println!("{}", h);
                    }
                    print_advice(name, &hashes);
                }
                _ => {
                    eprintln!("Converter '{}' produced no output for '{}'", name, path);
                    process::exit(1);
                }
            }
        }
        None => {
            // Try all converters as fallback
            eprintln!("[*] Unknown type — trying self-identifying converters...");
            let mut found = false;
            for name in converters::all_names() {
                // Loosely-matching converters are excluded here on purpose: in a
                // blind sweep the first one to say "yes" wins, so a permissive
                // converter would mask every later, correct one.
                if !converters::fallback_safe(name) {
                    continue;
                }
                if let Some(hashes) = converters::run(name, &data, path) {
                    if !hashes.is_empty() {
                        eprintln!("[*] {} matched:", name);
                        for h in &hashes {
                            println!("{}", h);
                        }
                        print_advice(name, &hashes);
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                eprintln!("No matching converter found for '{}'", path);
                process::exit(1);
            }
        }
    }
}

fn identify_hash_string(s: &str) {
    let results = detect::identify_hash(s);
    if results.is_empty() {
        eprintln!("Unknown hash format: {}", s);
        process::exit(1);
    }
    println!("Hash: {}", s);
    println!("Possible types:");
    for (name, mode) in &results {
        println!("  {} (hashcat -m {})", name, mode);
    }
}
