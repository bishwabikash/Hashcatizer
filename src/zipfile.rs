//! Minimal ZIP reader for the document formats.
//!
//! ODF, StarOffice and iWork containers are ZIP archives whose crackable
//! material is described by an XML manifest inside them. Only reading a named
//! entry is needed, so this walks the central directory directly rather than
//! pulling in a full archive crate.
//!
//! Only STORED and DEFLATE are supported — the two methods these formats use.

use crate::common::{u16_le, u32_le};

const CD_SIG: &[u8] = b"PK\x01\x02";
const LFH_SIG: &[u8] = b"PK\x03\x04";

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// Read one entry by name, decompressing if necessary.
pub fn read_entry(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let (lfh_off, comp_size, method) = find_in_central_directory(data, name)?;

    // The local header repeats the name and extra fields with its own lengths,
    // which are what actually locate the payload.
    if data.get(lfh_off..lfh_off + 4)? != LFH_SIG {
        return None;
    }
    let name_len = u16_le(data, lfh_off + 26) as usize;
    let extra_len = u16_le(data, lfh_off + 28) as usize;
    let start = lfh_off.checked_add(30)?.checked_add(name_len)?.checked_add(extra_len)?;
    let body = data.get(start..start.checked_add(comp_size)?)?;

    match method {
        METHOD_STORED => Some(body.to_vec()),
        METHOD_DEFLATE => inflate(body),
        _ => None,
    }
}

/// Returns (local header offset, compressed size, method) for `name`.
fn find_in_central_directory(data: &[u8], name: &str) -> Option<(usize, usize, u16)> {
    let mut scan = 0usize;
    while let Some(rel) = data.get(scan..)?.windows(4).position(|w| w == CD_SIG) {
        let cd = scan + rel;
        // Fixed part of a central-directory record is 46 bytes.
        let Some(_) = data.get(cd..cd + 46) else { break };

        let method = u16_le(data, cd + 10);
        let comp_size = u32_le(data, cd + 20) as usize;
        let name_len = u16_le(data, cd + 28) as usize;
        let extra_len = u16_le(data, cd + 30) as usize;
        let comment_len = u16_le(data, cd + 32) as usize;
        let lfh_off = u32_le(data, cd + 42) as usize;

        if let Some(entry_name) = data.get(cd + 46..cd + 46 + name_len) {
            if entry_name == name.as_bytes() {
                return Some((lfh_off, comp_size, method));
            }
        }
        scan = cd + 46 + name_len + extra_len + comment_len;
        if scan <= cd {
            break; // malformed record: refuse to loop
        }
    }
    None
}

fn inflate(body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(body)
        .take(1 << 26) // guard against a decompression bomb
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

/// Value of `attr` on the XML element containing `anchor`, searching forward.
///
/// The manifests here are flat and attribute-only, so a scan is enough and
/// avoids a namespace-aware parser for what amounts to six lookups.
pub fn xml_attr_after(xml: &str, anchor: usize, attr: &str) -> Option<String> {
    let needle = format!("{}=\"", attr);
    let window = &xml[anchor..xml.len().min(anchor + 4096)];
    let at = window.find(&needle)? + needle.len();
    let rest = &window[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
