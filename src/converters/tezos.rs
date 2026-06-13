pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let esk = v["encrypted_secret_key"].as_str()
        .or_else(|| v["data"]["encrypted_secret_key"].as_str())?;
    Some(vec![format!("$tezos$0*{}", esk)])
}
