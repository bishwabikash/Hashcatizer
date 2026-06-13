use std::path::Path;
use std::process;

mod common;
mod detect;
mod converters;

// Hashcat mode hints for quick reference
fn hashcat_mode_hint(name: &str) -> Option<&'static str> {
    match name {
        "ansible"           => Some("16900"),
        "bitcoin"           => Some("11300"),
        "bitlocker"         => Some("22100"),
        "bitwarden"         => Some("26400"),
        "blockchain"        => Some("15200"),
        "dmg"               => Some("12700"),
        "electrum"          => Some("16600"),
        "encfs"             => Some("6211-6221"),
        "ethereum"          => Some("15600/15700"),
        "ios"               => Some("14800"),
        "keepass"           => Some("13400"),
        "lastpass"          => Some("6800"),
        "lion"              => Some("7100"),
        "luks"              => Some("14600"),
        "mac"               => Some("7100"),
        "mozilla"           => Some("16600"),
        "office"            => Some("9400/9500/9600/9700/9800"),
        "1password"         => Some("8200"),
        "pcap"              => Some("5500/5600"),
        "pdf"               => Some("10400/10500/10600/10700"),
        "pgpdisk"           => Some("22600"),
        "pgpsda"            => Some("22600"),
        "pgpwde"            => Some("22600"),
        "pwsafe"            => Some("5200"),
        "sap"               => Some("7700/7800"),
        "7z"                => Some("11600"),
        "signal"            => Some("25300"),
        "ssh"               => Some("22911/22921/22931/22941"),
        "telegram"          => Some("22301"),
        "truecrypt"         => Some("6211-6243"),
        "vdi"               => Some("13711-13733"),
        "veracrypt"         => Some("13711-13743"),
        "zed"               => Some("13711"),
        "androidbackup"     => Some("18900"),
        "androidfde"        => Some("12900"),
        "axcrypt"           => Some("13200"),
        "bestcrypt"         => Some("23400"),
        "cardano"           => Some("28500"),
        "deepsound"         => Some("24310"),
        "diskcryptor"       => Some("22500"),
        "dpapimk"           => Some("15300/15900"),
        "ecryptfs"          => Some("12200"),
        "enpass"            => Some("24600"),
        "fvde"              => Some("16700"),
        "geli"              => Some("16800"),
        "iwork"             => Some("9600"),
        "keychain"          => Some("23100"),
        "libreoffice"       => Some("18400"),
        "monero"            => Some("26620"),
        "multibit"          => Some("22200"),
        "netntlm"           => Some("5500/5600"),
        "openssl_enc"       => Some("500"),
        "pfx"               => Some("24410"),
        "restic"            => Some("24410"),
        "sevenz"            => Some("11600"),
        "staroffice"        => Some("18400"),
        "strip"             => Some("24420"),
        "tezos"             => Some("28510"),
        "vmx"               => Some("17300"),
        "hccapx"            => Some("22000"),
        "zip"               => Some("13600"),
        "rar"               => Some("12500/13000"),
        "gpg"               => Some("17010"),
        _                   => None,
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
            if let Some(mode) = hashcat_mode_hint(name) {
                eprintln!("[*] Crack with: hashcat -m {} <hashfile> <wordlist>", mode);
            }
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
                    if let Some(mode) = hashcat_mode_hint(name) {
                        eprintln!("[*] Crack with: hashcat -m {} <hashfile> <wordlist>", mode);
                    }
                }
                _ => {
                    eprintln!("Converter '{}' produced no output for '{}'", name, path);
                    process::exit(1);
                }
            }
        }
        None => {
            // Try all converters as fallback
            eprintln!("[*] Unknown type — trying all converters...");
            let mut found = false;
            for name in converters::all_names() {
                if let Some(hashes) = converters::run(name, &data, path) {
                    if !hashes.is_empty() {
                        eprintln!("[*] {} matched:", name);
                        for h in &hashes {
                            println!("{}", h);
                        }
                        if let Some(mode) = hashcat_mode_hint(name) {
                            eprintln!("[*] Crack with: hashcat -m {} <hashfile> <wordlist>", mode);
                        }
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
