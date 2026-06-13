pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let v: serde_json::Value = serde_json::from_str(text).ok()?;

    if let Some(crypto) = v.get("crypto") {
        let kdf = crypto["kdf"].as_str().unwrap_or("scrypt");
        if kdf == "scrypt" {
            let params = &crypto["kdfparams"];
            let n = params["n"].as_u64()?;
            let r = params["r"].as_u64()?;
            let p = params["p"].as_u64()?;
            let salt = params["salt"].as_str()?;
            let ct   = crypto["ciphertext"].as_str()?;
            return Some(vec![format!("$keplr$scrypt*{}*{}*{}*{}*{}", n, r, p, salt, ct)]);
        } else {
            let params = &crypto["kdfparams"];
            let c    = params["c"].as_u64().unwrap_or(10000);
            let salt = params["salt"].as_str()?;
            let ct   = crypto["ciphertext"].as_str()?;
            return Some(vec![format!("$keplr$pbkdf2*{}*{}*{}", c, salt, ct)]);
        }
    }
    None
}
