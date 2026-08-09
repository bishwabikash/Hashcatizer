use crate::common::to_hex;

// Monero wallet .keys files -> $monero$ (john only).
//
//   $monero$0*<whole file, hex>
//
// The file has no magic and no internal structure the extractor can key off —
// john hands the entire blob to the cracker, which decrypts and checks it. The
// previous implementation emitted only the first 48 bytes and claimed hashcat
// mode 26620, which is MetaMask; hashcat has no Monero kernel at all.
//
// Because there is nothing to validate against, this converter is deliberately
// kept out of the auto-detect sweep and gated on the .keys extension.

pub fn convert(data: &[u8], filename: &str) -> Option<Vec<String>> {
    if data.is_empty() {
        return None;
    }
    // Monero wallets are small; a huge file is certainly something else.
    if data.len() > 1 << 20 {
        return None;
    }
    if !filename.to_ascii_lowercase().ends_with(".keys") {
        return None;
    }
    Some(vec![format!("$monero$0*{}", to_hex(data))])
}
