use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(b"%PDF") { return None; }
    let text = std::str::from_utf8(data).ok()?;

    // Extract /Encrypt reference and /ID from trailer
    let enc_ref = extract_encrypt_ref(text)?;
    let doc_id  = extract_doc_id(text)?;
    let enc_obj = find_object(text, enc_ref)?;

    let v   = get_pdf_int(enc_obj, "/V")?;
    let r   = get_pdf_int(enc_obj, "/R")?;
    let p   = get_pdf_int_signed(enc_obj, "/P")?;
    let key_len = get_pdf_int(enc_obj, "/Length").unwrap_or(if v >= 3 { 128 } else { 40 });
    let u_hex = get_pdf_hex_or_string(enc_obj, "/U")?;
    let _o_hex = get_pdf_hex_or_string(enc_obj, "/O")?;
    let enc_meta = if enc_obj.contains("/EncryptMetadata false") { 0 } else { 1 };

    Some(vec![format!(
        "$pdf${}*{}*{}*{}*{}*{}*{}*{}*{}",
        v, r, key_len, p, enc_meta,
        doc_id.len() / 2, doc_id,
        u_hex.len() / 2, u_hex
    )])
}

fn extract_encrypt_ref(text: &str) -> Option<u32> {
    let re = regex::Regex::new(r"/Encrypt\s+(\d+)\s+\d+\s+R").ok()?;
    let caps = re.captures(text)?;
    caps[1].parse().ok()
}

fn extract_doc_id(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"/ID\s*\[\s*<([0-9a-fA-F]+)>").ok()?;
    re.captures(text).map(|c| c[1].to_lowercase())
}

fn find_object(text: &str, obj_num: u32) -> Option<&str> {
    let pat = format!("{} ", obj_num);
    let pos = text.find(&pat)?;
    let end = text[pos..].find("endobj")? + pos + 6;
    Some(&text[pos..end])
}

fn get_pdf_int(obj: &str, key: &str) -> Option<u32> {
    let re = regex::Regex::new(&format!(r"{}\s+(-?\d+)", regex::escape(key))).ok()?;
    re.captures(obj)?[1].parse().ok()
}

fn get_pdf_int_signed(obj: &str, key: &str) -> Option<i32> {
    let re = regex::Regex::new(&format!(r"{}\s+(-?\d+)", regex::escape(key))).ok()?;
    re.captures(obj)?[1].parse().ok()
}

fn get_pdf_hex_or_string(obj: &str, key: &str) -> Option<String> {
    // Try <hex>
    let re_hex = regex::Regex::new(&format!(r"{}\s*<([0-9a-fA-F]+)>", regex::escape(key))).ok()?;
    if let Some(c) = re_hex.captures(obj) {
        return Some(c[1].to_lowercase());
    }
    // Try (string)
    let re_str = regex::Regex::new(&format!(r"{}\s*\(([^)]*)\)", regex::escape(key))).ok()?;
    if let Some(c) = re_str.captures(obj) {
        return Some(to_hex(c[1].as_bytes()));
    }
    None
}
