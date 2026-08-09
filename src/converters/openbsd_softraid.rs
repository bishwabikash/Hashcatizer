use crate::common::{to_hex, u32_le};

// OpenBSD softraid CRYPTO volumes -> $openbsd-softraid$ (john only; see
// docs/HASHCAT_GAPS.md).
//
//   $openbsd-softraid$<iterations>$<salt>$<masked keys>$<hmac>$<kdf_type>
//
// All offsets are fixed within the softraid metadata header. The masked-key
// block is 2048 bytes, so the whole thing is far larger than the 512-byte
// prefix the previous implementation dumped.

const KDF_TYPE_OFF: usize = 2416;
const ITERATIONS_OFF: usize = 2420;
const SALT: (usize, usize) = (2424, 2552);
const MASKED_KEYS: (usize, usize) = (364, 2412);
const HMAC: (usize, usize) = (2676, 2696);

/// PKCS#5 PBKDF2 with HMAC-SHA1 — the only KDF john can attack here.
const SR_CRYPTO_KDF_PKCS: u32 = 3;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < HMAC.1 {
        return None;
    }
    let kdf_type = u32_le(data, KDF_TYPE_OFF);
    if kdf_type != SR_CRYPTO_KDF_PKCS {
        return None;
    }
    let iterations = u32_le(data, ITERATIONS_OFF);
    // A zero or absurd iteration count means this is not a softraid header.
    if iterations == 0 || iterations > 10_000_000 {
        return None;
    }

    let salt = data.get(SALT.0..SALT.1)?;
    let masked_keys = data.get(MASKED_KEYS.0..MASKED_KEYS.1)?;
    let hmac = data.get(HMAC.0..HMAC.1)?;

    Some(vec![format!(
        "$openbsd-softraid${}${}${}${}${}",
        iterations,
        to_hex(salt),
        to_hex(masked_keys),
        to_hex(hmac),
        kdf_type
    )])
}
