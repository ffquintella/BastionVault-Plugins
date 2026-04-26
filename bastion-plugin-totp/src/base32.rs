//! RFC 4648 base32 (alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ234567) decode.
//! Whitespace and padding `=` are tolerated; lower-case input is folded
//! to upper. Returns `None` on any other invalid character.

use alloc::vec::Vec;

pub fn decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let value: u32 = match c {
            'A'..='Z' => (c as u32) - ('A' as u32),
            'a'..='z' => (c as u32) - ('a' as u32),
            '2'..='7' => (c as u32) - ('2' as u32) + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_test_vectors() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("MY======").unwrap(), b"f");
        assert_eq!(decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_non_alphabet() {
        assert!(decode("!!!").is_none());
        assert!(decode("abc1").is_none());
    }

    #[test]
    fn tolerates_whitespace_and_lowercase() {
        assert_eq!(decode("mz xw 6y tb").unwrap(), b"fooba");
    }
}
