pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let j: serde_json::Value = serde_json::from_slice(data).ok()?;
    let d = j.get("data")?.as_str()?;
    Some(vec![format!("$cardano${}", d)])
}
