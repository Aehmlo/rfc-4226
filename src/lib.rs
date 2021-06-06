//! Implementation of [IETF RFC 4226][4226], "HOTP: An HMAC-Based One-Time Password
//! Algorithm."
//!
//! # Examples
//!
//! [The workhorse `hotp` function][hotp] returns a [`Token`][Token] of the specified length:
//!
//! ```rust
//!# use rfc_4226::{hotp, Token};
//! let key = b"ferris23!@#$%^&*()";
//! let counter = 9001_u64;
//! let token: Token<6> = hotp(key, counter).unwrap();
//! assert_eq!(token, Token(852888));
//! ```
//!
//! The crate makes extensive use of ["const generics"][const-generics] to encode token lengths
//! in all operations, forcing consumers to specify exactly what, for instance, "is the token
//! equal to this number?" means. This explicitness also enables some nice features, such as
//! automatic zero-padding of tokens to the correct length for display to a user:
//!
//! ```rust
//!# use rfc_4226::{hotp, Token};
//! let key = b"ferris23!@#$%^&*()";
//! let counter = 292167_u64;
//! let token: Token<6> = hotp(key, counter).unwrap();
//! // Equivalent:
//! let token = hotp::<_, _, 6>(key, counter).unwrap();
//! assert_eq!(token.to_string(), "000000");
//! ```
//!
//! This type-level encoding is also used to ensure that the HOTP spec is followed closely
//! at compile time.
//!
//! ```rust,compile_fail
//!# use rfc_4226::{hotp, Token};
//! let key = b"ferris23!@#$%^&*()";
//! let counter = 9001_u64;
//! // The HOTP spec only allows tokens of length 6–9
//! let pin: Token<4> = hotp(key, counter).unwrap();
//! ```
//!
//! [4226]: https://datatracker.ietf.org/doc/html/rfc4226
//! [const-generics]: https://rust-lang.github.io/rfcs/2000-const-generics.html
#![no_std]

pub mod digest;
pub mod length;
use digest::{hmac_sha1, Digest as _};
use length::{Length, TokenLength};

/// HOTP token type.
///
/// Note that comparing tokens of different lengths will fail:
///
/// ```rust,compile_fail
///# use rfc_4226::Token;
/// assert_eq!(Token::<6>(0), Token::<7>(0));
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Token<const DIGITS: u8>(pub u32);

impl<const DIGITS: u8> core::fmt::Display for Token<DIGITS> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:01$}", self.0, DIGITS as usize)
    }
}

/// HOTP error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HotpError {
    ShortSecret(usize),
}

impl core::fmt::Display for HotpError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let Self::ShortSecret(len) = self;
        write!(
            f,
            "Shared secret length {} bits is too short (minimum: 128 bits)",
            len * 8
        )
    }
}

/// Main HOTP function.
///
/// This function takes an 8-byte `counter` element and a key (specified as a sequence of bytes)
/// and uses the HMAC-SHA1 digest method followed by truncation to produce an HOTP
/// [token][`Token`] of the desired number of `DIGITS`.
///
/// # Errors
///
/// Currently (and subject to change), the only possible error from this method results from
/// providing an invalid shared secret (`key`). According to [RFC 4226][4226], algorithm requirement 6:
///
/// > The length of the shared secret MUST be at least 128 bits. This document RECOMMENDS a
/// shared secret length of 160 bits.
///
/// As such, this method will return an error if the key is shorter than 16 bytes (128 bits).
///
/// # Extension to other digest protocols
///
/// While [RFC 4226][4226] technically only allows for the HMAC-SHA1 protocol, extensions such as
/// [RFC 6238][6238] (which describes TOTP) allow the use of other protocols. As such, this
/// crate pragmatically exposes a method for using other digest protocols in [the `Digest`
/// trait][`digest::Digest`]. To use other digest functions:
///
/// 1. implement [`Digest`][`digest::Digest`] for your type, and
/// 2. invoke [`Digest::truncate`][`digest::Digest::truncate`] on an instance of the type to
///    generate a [`Token`][`Token`].
///
/// So long as the digest is at least 16 bytes long, this should work without issue.
///
/// For those specifically interested in TOTP, see also [the companion `rfc-6238`
/// crate][rfc-6238].
///
/// [4226]: https://datatracker.ietf.org/doc/html/rfc4226
/// [6238]: https://datatracker.ietf.org/doc/html/rfc6238
/// [rfc-6238]: https://lib.rs/crates/rfc-6238
pub fn hotp<K, C, const DIGITS: u8>(key: K, counter: C) -> Result<Token<DIGITS>, HotpError>
where
    C: Into<u64>,
    K: AsRef<[u8]>,
    Length<DIGITS>: TokenLength,
{
    let key = key.as_ref();
    // R6: "The length of the shared secret MUST be at least 128 bits."
    if key.len() < 16 {
        return Err(HotpError::ShortSecret(key.len()));
    }
    Ok(hmac_sha1(key, counter.into()).truncate::<DIGITS>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_appendix_d() {
        fn generate(count: u64) -> Token<6> {
            hotp(b"12345678901234567890", count).unwrap()
        }
        assert_eq!(generate(0), Token(755224));
        assert_eq!(generate(1), Token(287082));
        assert_eq!(generate(2), Token(359152));
        assert_eq!(generate(3), Token(969429));
        assert_eq!(generate(4), Token(338314));
        assert_eq!(generate(5), Token(254676));
        assert_eq!(generate(6), Token(287922));
        assert_eq!(generate(7), Token(162583));
        assert_eq!(generate(8), Token(399871));
        assert_eq!(generate(9), Token(520489));
    }
}
