//! Minimal protobuf wire-format reader.
//!
//! bitcoinj wallets (MultiBit, Coinomi) are serialised protobuf, and the only
//! fields the converters need are length-delimited bytes and varints. Pulling in
//! a full protobuf stack plus generated code for that would be disproportionate,
//! and the wire format is self-describing enough to walk directly.
//!
//! Everything is bounds-checked: these are untrusted files.

pub const WIRE_VARINT: u8 = 0;
pub const WIRE_LEN: u8 = 2;

pub struct Field<'a> {
    pub number: u32,
    pub wire_type: u8,
    /// Payload for length-delimited fields; empty otherwise.
    pub bytes: &'a [u8],
    /// Decoded value for varint fields; 0 otherwise.
    pub varint: u64,
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn next(&mut self) -> Option<Field<'a>> {
        if self.pos >= self.data.len() {
            return None;
        }
        let key = self.varint()?;
        let number = (key >> 3) as u32;
        let wire_type = (key & 0x07) as u8;

        match wire_type {
            WIRE_VARINT => {
                let v = self.varint()?;
                Some(Field { number, wire_type, bytes: &[], varint: v })
            }
            WIRE_LEN => {
                let len = self.varint()? as usize;
                let end = self.pos.checked_add(len)?;
                let bytes = self.data.get(self.pos..end)?;
                self.pos = end;
                Some(Field { number, wire_type, bytes, varint: 0 })
            }
            1 => {
                // 64-bit
                let end = self.pos.checked_add(8)?;
                self.data.get(self.pos..end)?;
                self.pos = end;
                Some(Field { number, wire_type, bytes: &[], varint: 0 })
            }
            5 => {
                // 32-bit
                let end = self.pos.checked_add(4)?;
                self.data.get(self.pos..end)?;
                self.pos = end;
                Some(Field { number, wire_type, bytes: &[], varint: 0 })
            }
            // Groups are deprecated and absent from these wallets; refusing to
            // guess at them is safer than skipping an unknown length.
            _ => None,
        }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None // malformed: more than ten continuation bytes
    }
}

/// First field with `number` in a message.
pub fn find<'a>(data: &'a [u8], number: u32) -> Option<Field<'a>> {
    let mut r = Reader::new(data);
    while let Some(f) = r.next() {
        if f.number == number {
            return Some(f);
        }
    }
    None
}

/// Every field with `number` in a message.
pub fn find_all<'a>(data: &'a [u8], number: u32) -> Vec<Field<'a>> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    while let Some(f) = r.next() {
        if f.number == number {
            out.push(f);
        }
    }
    out
}
