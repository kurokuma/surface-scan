use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Random-enough identifier for one scan run, used to group output records.
pub fn scan_id() -> String {
    let seed = format!(
        "{}-{}-{:?}",
        std::process::id(),
        now_rfc3339(),
        std::time::SystemTime::now()
    );
    sha256_hex(seed).chars().take(16).collect()
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// MIME base64 with a line break every 76 characters and a trailing newline.
///
/// This reproduces Python's `codecs.encode(data, "base64")`, which is what the
/// public favicon-hash corpora (Shodan, Censys) hash.
fn base64_mime(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4 + data.len() / 57 + 2);
    let mut column = 0usize;
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64[(triple >> 18) as usize & 0x3f]);
        out.push(BASE64[(triple >> 12) as usize & 0x3f]);
        out.push(if chunk.len() > 1 {
            BASE64[(triple >> 6) as usize & 0x3f]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            BASE64[triple as usize & 0x3f]
        } else {
            b'='
        });
        column += 4;
        if column == 76 {
            out.push(b'\n');
            column = 0;
        }
    }
    if column != 0 {
        out.push(b'\n');
    }
    out
}

/// MurmurHash3 x86_32 with seed 0.
fn mmh3_x86_32(data: &[u8]) -> i32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut hash: u32 = 0;
    let mut blocks = data.chunks_exact(4);
    for block in blocks.by_ref() {
        let mut k = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        hash ^= k;
        hash = hash
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64);
    }
    let tail = blocks.remainder();
    if !tail.is_empty() {
        let mut k: u32 = 0;
        for (index, byte) in tail.iter().enumerate() {
            k |= (*byte as u32) << (8 * index);
        }
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        hash ^= k;
    }
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^= hash >> 16;
    hash as i32
}

/// Shodan-compatible favicon hash: mmh3 over the MIME-base64 of the icon bytes.
pub fn favicon_mmh3(data: &[u8]) -> i32 {
    mmh3_x86_32(&base64_mime(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base64_matches_mime_layout() {
        assert_eq!(base64_mime(b"hello"), b"aGVsbG8=\n");
        // 60 bytes encode to 80 characters, which wraps after 76.
        let wrapped = base64_mime(&[0u8; 60]);
        assert_eq!(wrapped.iter().filter(|b| **b == b'\n').count(), 2);
    }
    #[test]
    fn mmh3_matches_known_vectors() {
        assert_eq!(mmh3_x86_32(b""), 0);
        assert_eq!(mmh3_x86_32(b"hello"), 613_153_351);
        assert_eq!(mmh3_x86_32(b"hello, world"), 345_750_399);
        // Signed wrap-around is part of the contract: mmh3 hashes are published
        // as signed 32-bit integers.
        assert_eq!(mmh3_x86_32(b"foo"), -156_908_512);
    }
    #[test]
    fn favicon_hash_is_stable() {
        assert_eq!(favicon_mmh3(b"hello"), favicon_mmh3(b"hello"));
        assert_ne!(favicon_mmh3(b"hello"), favicon_mmh3(b"other"));
    }
}
