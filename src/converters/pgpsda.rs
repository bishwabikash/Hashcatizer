use crate::common::to_hex;

// struct SDAHEADER: magic(6) + offset(4) + comp_len(8) + num_files(8) + salt(8) + hash_reps(2) + check_bytes(8)
pub fn convert(data: &[u8], filename: &str) -> Option<Vec<String>> {
    if data.len() < 44 || &data[0..6] != b"PGPSDA" {
        return None;
    }
    let hash_reps = u16::from_le_bytes(data[34..36].try_into().ok()?);
    let salt        = to_hex(&data[26..34]);
    let check_bytes = to_hex(&data[36..44]);
    let basename = std::path::Path::new(filename)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    Some(vec![format!(
        "{}:$pgpsda$0*{}*{}*{}",
        basename, hash_reps, salt, check_bytes
    )])
}
