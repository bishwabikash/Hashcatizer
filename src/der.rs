//! Minimal DER reader — just enough to walk the PKCS#8 / PKCS#12 structures the
//! key converters need. Deliberately not a general ASN.1 implementation: it
//! handles definite-length primitives and constructed sequences, which is all
//! these formats use.
//!
//! Every accessor is bounds-checked and returns `None` rather than panicking,
//! because the input is an untrusted file.

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;

/// One TLV element.
pub struct Element<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

impl<'a> Element<'a> {
    /// Iterate the children of a constructed element.
    pub fn children(&self) -> Parser<'a> {
        Parser::new(self.value)
    }

    /// Value as a big-endian unsigned integer, for the small counts (iteration
    /// counts, key lengths) these formats carry.
    pub fn as_u64(&self) -> Option<u64> {
        let bytes = self.value.strip_prefix(&[0u8]).unwrap_or(self.value);
        if bytes.is_empty() || bytes.len() > 8 {
            return None;
        }
        Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    /// Object identifier rendered in dotted-decimal form.
    pub fn as_oid(&self) -> Option<String> {
        let first = *self.value.first()?;
        let mut out = format!("{}.{}", first / 40, first % 40);
        let mut acc: u64 = 0;
        for &b in &self.value[1..] {
            acc = acc.checked_mul(128)?.checked_add((b & 0x7f) as u64)?;
            if b & 0x80 == 0 {
                out.push_str(&format!(".{}", acc));
                acc = 0;
            }
        }
        Some(out)
    }
}

/// Sequential reader over a run of DER elements.
pub struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Parser { data, pos: 0 }
    }

    /// Next element, or None at the end of the buffer / on malformed input.
    pub fn next(&mut self) -> Option<Element<'a>> {
        let tag = *self.data.get(self.pos)?;
        let mut off = self.pos + 1;
        let first_len = *self.data.get(off)?;
        off += 1;

        let len = if first_len & 0x80 == 0 {
            first_len as usize
        } else {
            // Long form: low bits give how many bytes encode the length.
            let n = (first_len & 0x7f) as usize;
            if n == 0 || n > 4 {
                return None; // indefinite length is not valid DER
            }
            let bytes = self.data.get(off..off.checked_add(n)?)?;
            off += n;
            bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
        };

        let end = off.checked_add(len)?;
        let value = self.data.get(off..end)?;
        self.pos = end;
        Some(Element { tag, value })
    }

    /// Next element, requiring a specific tag.
    pub fn expect(&mut self, tag: u8) -> Option<Element<'a>> {
        let e = self.next()?;
        if e.tag == tag { Some(e) } else { None }
    }

    /// Peek the tag of the next element without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }
}

/// Parse a single top-level element out of a DER buffer.
pub fn parse(data: &[u8]) -> Option<Element<'_>> {
    Parser::new(data).next()
}
