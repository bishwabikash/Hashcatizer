// Passthrough for hash files that are already in a cracker's format.
//
// Only lines carrying a recognised "$name$" marker are emitted. The previous
// implementation accepted any line containing a colon, which meant it claimed
// essentially every text file it was handed and, being early in the converter
// list, masked the correct converter during auto-detect.

/// Markers this passthrough will forward. Anything unrecognised is skipped so
/// the file gets a chance to reach a converter that actually parses it.
const KNOWN_MARKERS: &[&str] = &[
    "$krb5pa$",
    "$krb5tgs$",
    "$krb5asrep$",
    "$krb5db$",
    "$NT$",
    "$sip$",
    "$ike$",
    "$radius$",
    "$xmpp-scram$",
    "$mongodb-scram$",
    "$sshng$",
    "$known_hosts$",
    "$dynamic_",
];

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if KNOWN_MARKERS.iter().any(|m| line.contains(m)) {
            hashes.push(line.to_string());
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
