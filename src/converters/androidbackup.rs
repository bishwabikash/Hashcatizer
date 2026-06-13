pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "ANDROID BACKUP" { return None; }
    let version    = lines.next()?.trim().to_string();
    let _compress  = lines.next()?;
    let encryption = lines.next()?.trim();
    if encryption == "none" { return None; }
    let user_salt  = lines.next()?.trim().to_string();
    let ck_salt    = lines.next()?.trim().to_string();
    let rounds     = lines.next()?.trim().to_string();
    let user_iv    = lines.next()?.trim().to_string();
    let mk_blob    = lines.next()?.trim().to_string();
    Some(vec![format!("$ab${}*{}*{}*{}*{}*{}", version, rounds, user_salt, ck_salt, user_iv, mk_blob)])
}
