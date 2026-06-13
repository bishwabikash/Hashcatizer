use crate::common::to_hex;
use rusqlite::Connection;

pub fn convert(_data: &[u8], path: &str) -> Option<Vec<String>> {
    let conn = Connection::open(path).ok()?;
    let mut out = Vec::new();

    let sql = "SELECT zicnotedata_id FROM ziccloudsyncingobject WHERE ziscornered = 1 LIMIT 20";
    if let Ok(mut stmt) = conn.prepare(sql) {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, i64>(0)) {
            for id in rows.flatten() {
                // Fetch note data
                if let Ok(blob) = conn.query_row(
                    "SELECT zdata FROM zicnotedata WHERE z_pk = ?1", [id],
                    |r| r.get::<_, Vec<u8>>(0))
                {
                    if blob.len() >= 64 {
                        // $ANP$<iters>*<salt>*<wrappedkey>*<iv>
                        // Use first 64 bytes as representative data
                        let iters = 20000u32;
                        let salt  = to_hex(&blob[..16]);
                        let wk    = to_hex(&blob[16..48]);
                        let iv    = to_hex(&blob[48..64]);
                        out.push(format!("$ANP${}*{}*{}*{}", iters, salt, wk, iv));
                    }
                }
            }
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
