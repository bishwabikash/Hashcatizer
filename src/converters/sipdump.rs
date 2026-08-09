// sipdump capture files -> hashcat -m 11400 (SIP digest authentication, MD5).
//
//   $sip$*<14 fields>
//
// A sipdump line is colon- and quote-delimited; both separators are rewritten
// to '*' so the fields land in the order the cracker expects. Lines carrying 13
// fields predate the extra URI component and get an empty one spliced in at
// index 7, exactly as sipdump2john does.

/// Older sipdump builds omit one URI component; those lines get it spliced back
/// in at index 7.
const SHORT_FIELDS: usize = 13;
/// Minimum field count for a line to be sipdump output at all.
const MIN_FIELDS: usize = 13;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // A bare "sip:*" would collide with the field separator introduced below.
        let normalised = line.replace("sip:*", "sip:0.0.0.0");
        let normalised = normalised.replace(['"', ':'], "*");

        let mut fields: Vec<String> = normalised.split('*').map(|s| s.to_string()).collect();
        if fields.len() == SHORT_FIELDS {
            fields.insert(7, String::new());
        }
        // Every sipdump line ends in the MD5 response digest. Requiring it keeps
        // this from claiming arbitrary colon-separated text, which is what the
        // original "line contains ':'" implementation did.
        let is_digest = fields
            .last()
            .is_some_and(|f| f.len() == 32 && f.chars().all(|c| c.is_ascii_hexdigit()));
        if fields.len() < MIN_FIELDS || !is_digest {
            continue;
        }
        out.push(format!("$sip$*{}", fields.join("*")));
    }
    if out.is_empty() { None } else { Some(out) }
}
