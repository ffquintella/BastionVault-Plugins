//! RFC 6238 TOTP / RFC 4226 HOTP — HMAC-SHA1, dynamic truncation,
//! mod 10^digits. Pure compute; no I/O.

use alloc::format;
use alloc::string::String;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub fn format_code(secret: &[u8], step: u64, digits: u32) -> String {
    let counter = step.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&counter);
    let hash = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 §5.3.
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin_code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulus = 10u32.pow(digits);
    let value = bin_code % modulus;
    format!("{:0width$}", value, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B — HMAC-SHA1, key = ASCII "12345678901234567890",
    /// digits = 8.
    fn key() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }

    #[test]
    fn rfc6238_appendix_b_sha1_t59() {
        // T = 59 / 30 = 1
        assert_eq!(format_code(&key(), 1, 8), "94287082");
    }

    #[test]
    fn rfc6238_appendix_b_sha1_t1111111109() {
        // T = 1111111109 / 30 = 37037036
        assert_eq!(format_code(&key(), 37037036, 8), "07081804");
    }

    #[test]
    fn rfc6238_appendix_b_sha1_t1111111111() {
        // T = 1111111111 / 30 = 37037037
        assert_eq!(format_code(&key(), 37037037, 8), "14050471");
    }

    #[test]
    fn rfc6238_appendix_b_sha1_t1234567890() {
        // T = 1234567890 / 30 = 41152263
        assert_eq!(format_code(&key(), 41152263, 8), "89005924");
    }

    #[test]
    fn six_digit_truncation_matches_last_six_of_eight() {
        assert_eq!(format_code(&key(), 1, 6), "287082");
    }
}
