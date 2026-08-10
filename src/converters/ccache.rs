use crate::common::to_hex;
use crate::der::{Element, Parser, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE};

// MIT Kerberos credential caches -> hashcat -m 13100 (etype 23 TGS-REP).
//
//   $krb5tgs$<etype>$<checksum>$<edata>
//
// The cache is a sequence of credentials, each carrying a DER-encoded Ticket
// whose enc-part holds the material to attack. Both layers have to be walked:
// the binary container to reach each ticket, then ASN.1 to reach its cipher.
// The previous implementation hex-dumped the first 512 bytes of the file.
//
// Service principals that are not user-service tickets are skipped: a krbtgt
// entry is encrypted under the KDC key, not a crackable account password.

const V3: u16 = 0x0503;
const V4: u16 = 0x0504;

/// [APPLICATION 1] constructed — Ticket.
const TAG_TICKET: u8 = 0x61;
const CTX0: u8 = 0xa0;
const CTX2: u8 = 0xa2;
const CTX3: u8 = 0xa3;

/// etype 23 (RC4-HMAC) is what -m 13100 cracks.
const ETYPE_RC4_HMAC: u64 = 23;

const SKIP_SERVICES: [&str; 3] = ["krbtgt", "krb5_ccache_conf_data", "pa_type"];

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let mut r = Cursor { data, pos: 0 };

    let version = r.u16()?;
    if version != V3 && version != V4 {
        return None;
    }
    if version == V4 {
        // Tagged header block, present only in v4.
        let header_len = r.u16()? as usize;
        r.skip(header_len)?;
    }
    r.principal()?; // default principal

    let mut out = Vec::new();
    while r.pos < data.len() {
        let Some(cred) = r.credential(version) else {
            break; // truncated or unexpected structure: stop cleanly
        };
        if cred.service_names.iter().any(|n| SKIP_SERVICES.contains(&n.as_str())) {
            continue;
        }
        let Some((etype, cipher)) = ticket_encpart(&cred.ticket) else {
            continue;
        };
        if etype != ETYPE_RC4_HMAC || cipher.len() <= 16 {
            continue;
        }
        out.push(format!(
            "$krb5tgs${}${}${}",
            etype,
            to_hex(&cipher[..16]),
            to_hex(&cipher[16..])
        ));
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Ticket -> enc-part[3] -> (etype[0], cipher[2])
fn ticket_encpart(ticket: &[u8]) -> Option<(u64, Vec<u8>)> {
    let outer = Parser::new(ticket).next()?;
    if outer.tag != TAG_TICKET {
        return None;
    }
    let body = child(&outer, TAG_SEQUENCE)?;
    let enc_part = child(&body, CTX3)?;
    let enc_body = child(&enc_part, TAG_SEQUENCE)?;

    let etype = child(&enc_body, CTX0)?;
    let etype = child(&etype, TAG_INTEGER)?.as_u64()?;

    let cipher_ctx = child(&enc_body, CTX2)?;
    let cipher = child(&cipher_ctx, TAG_OCTET_STRING)?;
    Some((etype, cipher.value.to_vec()))
}

fn child<'a>(parent: &Element<'a>, tag: u8) -> Option<Element<'a>> {
    let mut p = parent.children();
    while let Some(e) = p.next() {
        if e.tag == tag {
            return Some(e);
        }
    }
    None
}

struct Credential {
    service_names: Vec<String>,
    ticket: Vec<u8>,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u16(&mut self) -> Option<u16> {
        let b = self.data.get(self.pos..self.pos.checked_add(2)?)?;
        self.pos += 2;
        Some(u16::from_be_bytes(b.try_into().ok()?))
    }

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

    /// A u32 length followed by that many bytes.
    fn counted(&mut self) -> Option<&[u8]> {
        let len = self.u32()? as usize;
        let end = self.pos.checked_add(len)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Principal: name type, component count, realm, then the components.
    /// Returns the component strings, which name the service.
    fn principal(&mut self) -> Option<Vec<String>> {
        let _name_type = self.u32()?;
        let count = self.u32()? as usize;
        if count > 64 {
            return None;
        }
        self.counted()?; // realm
        let mut parts = Vec::with_capacity(count);
        for _ in 0..count {
            let c = self.counted()?;
            parts.push(String::from_utf8_lossy(c).to_string());
        }
        Some(parts)
    }

    fn credential(&mut self, version: u16) -> Option<Credential> {
        self.principal()?; // client
        let service_names = self.principal()?; // server

        // keyblock: keytype, (etype only in v3), keylen, key
        self.u16()?;
        if version == V3 {
            self.u16()?;
        }
        let keylen = self.u16()? as usize;
        self.skip(keylen)?;

        self.skip(4 * 4)?; // authtime, starttime, endtime, renew_till
        self.skip(1)?; // is_skey
        self.u32()?; // tktflags

        let num_address = self.u32()? as usize;
        for _ in 0..num_address {
            self.u16()?; // addrtype
            self.counted()?;
        }
        let num_authdata = self.u32()? as usize;
        for _ in 0..num_authdata {
            self.u16()?; // ad_type
            self.counted()?;
        }

        let ticket = self.counted()?.to_vec();
        self.counted()?; // second_ticket

        Some(Credential { service_names, ticket })
    }
}
