use crate::common::{to_hex, b64_decode};

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if !data.starts_with(b"PK\x03\x04") { return None; }
    let manifest_marker = b"META-INF/manifest.xml";
    let pos = data.windows(manifest_marker.len()).position(|w| w == manifest_marker)?;
    // Scan forward for XML content
    let xml_start = pos + manifest_marker.len();
    let xml_data  = &data[xml_start..data.len().min(xml_start + 4096)];
    let xml       = std::str::from_utf8(xml_data).ok()?;

    macro_rules! attr {
        ($name:expr) => { extract_xml_attr(xml, $name) };
    }
    let iv_b64   = attr!("initialisation-vector")?;
    let salt_b64 = attr!("salt")?;
    let iters: u32   = attr!("iteration-count")?.parse().ok()?;
    let key_size: u32= attr!("key-size")?.parse().ok()?;
    let chk_b64  = attr!("checksum")?;

    let iv_hex   = to_hex(&b64_decode(&iv_b64).ok()?);
    let salt_raw = b64_decode(&salt_b64).ok()?;
    let chk_hex  = to_hex(&b64_decode(&chk_b64).ok()?);

    Some(vec![format!(
        "$odf$*0*0*{}*{}*{}*{}*{}*{}",
        iters, key_size, chk_hex,
        salt_raw.len(), to_hex(&salt_raw), iv_hex
    )])
}

fn extract_xml_attr(xml: &str, name: &str) -> Option<String> {
    let pat = format!("{}=\"", name);
    let s = xml.find(&pat)? + pat.len();
    let e = xml[s..].find('"')? + s;
    Some(xml[s..e].to_string())
}
