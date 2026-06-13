pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let j: serde_json::Value = serde_json::from_slice(data).ok()?;
    let user = j.get("user").and_then(|v| v.as_str()).unwrap_or("user");
    let creds = j.get("credentials")?;
    let mut hashes = Vec::new();
    for algo in &["SCRAM-SHA-1", "SCRAM-SHA-256"] {
        if let Some(c) = creds.get(algo) {
            let iters = c.get("iterationCount")?.as_u64()?;
            let salt  = c.get("salt")?.as_str()?;
            let sk    = c.get("storedKey")?.as_str()?;
            let svk   = c.get("serverKey")?.as_str()?;
            hashes.push(format!(
                "$mongodb-scram${}*{}*{}*{}*{}*{}",
                algo, user, iters, salt, sk, svk
            ));
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
