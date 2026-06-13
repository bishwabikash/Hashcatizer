pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let kdf = v.get("kdf")?;
    let n: u64 = parse_int(&kdf["N"])?;
    let r: u64 = parse_int(&kdf["r"])?;
    let p: u64 = parse_int(&kdf["p"])?;
    let salt = kdf["salt"].as_str()?;
    let data_b64 = v["mac"]["data"].as_str()?;
    Some(vec![format!("$restic${}*{}*{}*{}*{}", n, r, p, salt, data_b64)])
}

fn parse_int(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}
