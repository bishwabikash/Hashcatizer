use crate::common::to_hex;
use crate::der::{Element, Parser, TAG_OCTET_STRING, TAG_SEQUENCE};

// Mimikatz .kirbi tickets (KRB-CRED) -> hashcat -m 13100.
//
//   $krb5tgs$23$*<name>*$<checksum:16 bytes>$<edata>
//
// The encrypted ticket is reached by walking
//   KRB-CRED[APPLICATION 22] -> tickets[2] -> Ticket[APPLICATION 1]
//                            -> enc-part[3] -> cipher[2]
// which is also what makes this safe in the auto-detect sweep. The previous
// version accepted any file starting with 0x30 — every certificate, PKCS#12
// bundle and DER key in existence — and emitted a "$krb5tgs$0*unknown*" line
// that is not a valid hashcat format at all.

/// [APPLICATION 22] constructed — KRB-CRED.
const TAG_KRB_CRED: u8 = 0x76;
/// [APPLICATION 1] constructed — Ticket.
const TAG_TICKET: u8 = 0x61;
/// Context-specific constructed tags.
const CTX2: u8 = 0xa2;
const CTX3: u8 = 0xa3;

pub fn convert(data: &[u8], filename: &str) -> Option<Vec<String>> {
    if data.first() != Some(&TAG_KRB_CRED) {
        return None;
    }
    let cipher = extract_cipher(data)?;
    // hashcat splits the encrypted blob into a 16-byte checksum and the rest.
    if cipher.len() <= 16 {
        return None;
    }
    let name = std::path::Path::new(filename)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ticket".to_string());

    Some(vec![format!(
        "$krb5tgs$23$*{}*${}${}",
        name,
        to_hex(&cipher[..16]),
        to_hex(&cipher[16..])
    )])
}

fn extract_cipher(data: &[u8]) -> Option<Vec<u8>> {
    let krb_cred = Parser::new(data).next()?;
    let body = child(&krb_cred, TAG_SEQUENCE)?;

    let tickets = child(&body, CTX2)?; // tickets [2] SEQUENCE OF Ticket
    let list = child(&tickets, TAG_SEQUENCE)?;
    let ticket = child(&list, TAG_TICKET)?; // first Ticket
    let ticket_body = child(&ticket, TAG_SEQUENCE)?;

    let enc_part = child(&ticket_body, CTX3)?; // enc-part [3] EncryptedData
    let enc_body = child(&enc_part, TAG_SEQUENCE)?;

    let cipher_ctx = child(&enc_body, CTX2)?; // cipher [2] OCTET STRING
    let octets = child(&cipher_ctx, TAG_OCTET_STRING)?;
    Some(octets.value.to_vec())
}

/// First direct child carrying `tag`.
fn child<'a>(parent: &Element<'a>, tag: u8) -> Option<Element<'a>> {
    let mut p = parent.children();
    while let Some(e) = p.next() {
        if e.tag == tag {
            return Some(e);
        }
    }
    None
}
