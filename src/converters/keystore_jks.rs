use crate::common::to_hex;

// Java KeyStore (JKS) -> $keystore$ (john only; hashcat's -m 15500 is
// $jksprivk$, a different extraction — see docs/HASHCAT_GAPS.md).
//
//   $keystore$0$<len>$<store bytes>$<sha1>$<nkeys>$<keysize>$<key>
//
// The store password protects a SHA-1 over the whole file, so the entry table
// has to be walked to find where the digest starts. The previous implementation
// emitted a SHA-1 of nothing in particular followed by a fixed byte range.

const MAGIC: u32 = 0xfeed_feed;
const VERSION_1: u32 = 1;
const VERSION_2: u32 = 2;
const DIGEST_LEN: usize = 20;

const TAG_PRIVATE_KEY: u32 = 1;
const TAG_TRUSTED_CERT: u32 = 2;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let mut r = Reader { data, pos: 0 };

    if r.u32()? != MAGIC {
        return None;
    }
    let version = r.u32()?;
    if version != VERSION_1 && version != VERSION_2 {
        return None;
    }
    let count = r.u32()?;
    if count > 1 << 16 {
        return None;
    }

    // The container hash uses the first private key, if there is one.
    let mut first_key: Option<Vec<u8>> = None;

    for _ in 0..count {
        match r.u32()? {
            TAG_PRIVATE_KEY => {
                r.utf_string()?; // alias
                r.skip(8)?; // creation date
                let key = r.length_prefixed()?.to_vec();
                let num_certs = r.u32()?;
                for _ in 0..num_certs {
                    if version == VERSION_2 {
                        r.utf_string()?; // certificate type
                    }
                    r.length_prefixed()?;
                }
                if first_key.is_none() {
                    first_key = Some(key);
                }
            }
            TAG_TRUSTED_CERT => {
                r.utf_string()?;
                r.skip(8)?;
                if version == VERSION_2 {
                    r.utf_string()?;
                }
                r.length_prefixed()?;
            }
            _ => return None, // unrecognised entry: not a JKS we understand
        }
    }

    // Everything up to here is what the digest covers.
    let pos = r.pos;
    let digest = data.get(pos..pos + DIGEST_LEN)?;

    let (nkeys, keysize, keydata) = match &first_key {
        Some(k) => (1, k.len(), to_hex(k)),
        None => (0, 0, String::new()),
    };

    Some(vec![format!(
        "$keystore$0${}${}${}${}${}${}",
        pos,
        to_hex(data.get(..pos)?),
        to_hex(digest),
        nkeys,
        keysize,
        keydata
    )])
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let b = self.data.get(self.pos..self.pos.checked_add(4)?)?;
        self.pos += 4;
        Some(u32::from_be_bytes(b.try_into().ok()?))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    /// Java's modified-UTF8 string: a big-endian u16 length then the bytes.
    fn utf_string(&mut self) -> Option<&'a [u8]> {
        let b = self.data.get(self.pos..self.pos.checked_add(2)?)?;
        self.pos += 2;
        let len = u16::from_be_bytes(b.try_into().ok()?) as usize;
        let end = self.pos.checked_add(len)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// A big-endian u32 length followed by that many bytes.
    fn length_prefixed(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self.pos.checked_add(len)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
}
