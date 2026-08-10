use crate::common::{b64_decode, to_hex};
use crate::zipfile;

// StarOffice / early OpenOffice documents (.sxc .sdw .sxw .sxd .sxi)
// -> $sxc$ (john; hashcat's -m 18400 is modern ODF only).
//
//   $sxc$*<alg>*<checksum type>*<iterations>*<key size>*<checksum>
//        *<iv len>*<iv>*<salt len>*<salt>*<original length>*<length>*<content>
//
// The container is a ZIP whose META-INF/manifest.xml describes how content.xml
// was encrypted. Blowfish CFB is the only algorithm this generation used, and
// john supports nothing else, so anything different is rejected.

const MANIFEST: &str = "META-INF/manifest.xml";
const TARGET: &str = "content.xml";
const ALGORITHM: &str = "Blowfish CFB";
const KEY_SIZE: u32 = 16;
/// john truncates the sample it cracks against to one kilobyte.
const MAX_SAMPLE: usize = 1024;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let manifest = zipfile::read_entry(data, MANIFEST)?;
    let xml = std::str::from_utf8(&manifest).ok()?;

    // The encryption attributes live on the elements following the entry for
    // content.xml, so anchor there and read forward.
    let anchor = xml.find(&format!("full-path=\"{}\"", TARGET))?;

    let algorithm = zipfile::xml_attr_after(xml, anchor, "manifest:algorithm-name")
        .or_else(|| zipfile::xml_attr_after(xml, anchor, "algorithm-name"))?;
    if algorithm != ALGORITHM {
        return None;
    }

    let checksum = attr_hex(xml, anchor, "checksum")?;
    let iv = attr_hex(xml, anchor, "initialisation-vector")?;
    let salt = attr_hex(xml, anchor, "salt")?;
    let iterations = attr(xml, anchor, "iteration-count")?;
    if iterations.is_empty() || !iterations.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let content = zipfile::read_entry(data, TARGET)?;
    let mut original_length = content.len();
    let mut body = content;

    let length = if original_length >= MAX_SAMPLE {
        original_length = MAX_SAMPLE;
        MAX_SAMPLE
    } else {
        // Blowfish is a 64-bit block cipher, so a short tail is padded out.
        let pad = original_length % 8;
        if pad > 0 {
            body.extend(std::iter::repeat_n(b'0', pad));
        }
        body.len()
    };
    let sample = body.get(..length)?;

    Some(vec![format!(
        "$sxc$*0*0*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
        iterations,
        KEY_SIZE,
        checksum,
        iv.len() / 2,
        iv,
        salt.len() / 2,
        salt,
        original_length,
        length,
        to_hex(sample)
    )])
}

/// Manifest attributes are base64; the hash carries them as hex.
fn attr_hex(xml: &str, anchor: usize, name: &str) -> Option<String> {
    let raw = attr(xml, anchor, name)?;
    Some(to_hex(&b64_decode(&raw).ok()?))
}

fn attr(xml: &str, anchor: usize, name: &str) -> Option<String> {
    zipfile::xml_attr_after(xml, anchor, &format!("manifest:{}", name))
        .or_else(|| zipfile::xml_attr_after(xml, anchor, name))
}
