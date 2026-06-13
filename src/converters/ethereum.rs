pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let j: serde_json::Value = serde_json::from_slice(data).ok()?;
    let crypto = j.get("crypto").or_else(|| j.get("Crypto"))?;
    let kdf    = crypto.get("kdf")?.as_str()?;
    let params = crypto.get("kdfparams")?;
    let ct     = crypto.get("ciphertext")?.as_str()?;
    let mac    = crypto.get("mac")?.as_str()?;

    let hash = match kdf {
        "scrypt" => {
            let n    = params.get("n")?.as_u64()?;
            let r    = params.get("r")?.as_u64()?;
            let p    = params.get("p")?.as_u64()?;
            let salt = params.get("salt")?.as_str()?;
            format!("$ethereum$s*{}*{}*{}*{}*{}*{}", n, r, p, salt, ct, mac)
        }
        "pbkdf2" => {
            let c    = params.get("c")?.as_u64()?;
            let salt = params.get("salt")?.as_str()?;
            format!("$ethereum$p*{}*{}*{}*{}", c, salt, ct, mac)
        }
        _ => return None,
    };
    Some(vec![hash])
}
