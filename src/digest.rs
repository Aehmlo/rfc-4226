//! HMAC digest types and traits.

use core::convert::{TryFrom, TryInto as _};

use ring::hmac::{sign, Key as HmacKey, Tag, HMAC_SHA1_FOR_LEGACY_USE_ONLY as HMAC_SHA1};

use super::Token;
use crate::length::{Length, TokenLength};

/// HMAC-SHA1 digest type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HmacSha1(pub [u8; 20]);

impl AsRef<[u8]> for HmacSha1 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Digest for HmacSha1 {}

/// Trait enabling use of alternative digest algorithms.
///
/// [RFC 4226][4226] prescribes HMAC-SHA1 as the digest method. However, [RFC 6238][6238] extends
/// HOTP to allow the HMAC-SHA256 and HMAC-SHA512 methods, and it is otherwise conceivable that
/// other digest methods may be desired instead of HMAC-SHA1. As such, out of pragmatism,
/// `Digest` is a trait in this crate rather than a concrete type.
///
/// Under the strictest interpretation of RFC 4226, [the provided `HmacSha1` type][`HmacSha1`]
/// is the only type which should be used with the methods provided in this crate.
///
/// # Notes
///
/// Implementors should take care that their digests are always at least 16 bytes long, or
/// [`Digest::truncate` will panic](#panics).
///
/// [4226]: https://datatracker.ietf.org/doc/html/rfc4226
/// [6238]: https://datatracker.ietf.org/doc/html/rfc6238
pub trait Digest: AsRef<[u8]> {
    /// Truncate an HMAC digest to an appropriate HOTP token length.
    ///
    /// This method uses the internal `TokenLength` trait to ensure that only tokens of allowable
    /// length are generated. Per [RFC 4226][4226], the allowed lengths are 6, 7, 8, or 9 digits.
    ///
    /// [4226]: https://datatracker.ietf.org/doc/html/rfc4226
    ///
    /// # Panics
    ///
    /// Attempting to truncate a digest of length less than 16 bytes will unconditionally trigger
    /// a panic. This will never occur using the provided [`HmacSha1`][`HmacSha1`] type,
    /// but could conceivably occur for foreign implementations.
    ///
    /// # Examples
    ///
    /// Attempts to truncate a digest to too short a code will fail at compile time:
    ///
    /// ```rust,compile_fail
    ///# use rfc_4226::digest::{Digest, HmacSha1};
    ///# let digest: HmacSha1 = todo!();
    /// digest.truncate::<5>(digest);
    /// ```
    ///
    /// Codes of length 6, 7, 8, and 9 are allowed:
    ///
    /// ```rust,no_run
    ///# use rfc_4226::digest::{Digest, HmacSha1};
    ///# let digest: HmacSha1 = todo!();
    /// digest.truncate::<6>();
    /// digest.truncate::<7>();
    /// digest.truncate::<8>();
    /// digest.truncate::<9>();
    /// ```
    ///
    /// Lengths of 10 or greater are not:
    ///
    /// ```rust,compile_fail
    ///# use rfc_4226::digest::{Digest, HmacSha1};
    ///# let digest: HmacSha1 = todo!();
    /// truncate::<10>(digest);
    /// ```
    fn truncate<const DIGITS: u8>(&self) -> Token<DIGITS>
    where
        Length<DIGITS>: TokenLength,
    {
        let digest = self.as_ref();
        let len = digest.len();
        // Avoid spurious out-of-bounds-related panics by unconditionally panicking for
        // insufficiently long digests (since we're using four bits to form an index, we need at
        // least 16 bytes to be safe).
        assert!(len >= 16);
        // Dynamic truncation: use the four lowest-order bits of the digest to calculate the offset
        // for indexing
        let index = (digest[len - 1] & 0xf) as usize;
        // Manually construct array of four bytes for eventual const-ness
        let bytes = [
            // Strip leading bit to remove signed/unsigned ambiguity
            digest[index] & 0x7f,
            digest[index + 1],
            digest[index + 2],
            digest[index + 3],
        ];

        // Reduce modulo 10^digits
        let num = u32::from_be_bytes(bytes);
        Token(num % (10_u32.pow(DIGITS as u32)))
    }
}

impl From<[u8; 20]> for HmacSha1 {
    fn from(raw: [u8; 20]) -> Self {
        Self(raw)
    }
}

/// HMAC-SHA1 digest conversion error type.
///
/// This error indicates that an attempt to convert a sequence of bytes into an HMAC-SHA1 digest
/// failed. This occurs when the length of the sequence is something other than 20 bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha1Error {}

impl core::fmt::Display for Sha1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Invalid HMAC-SHA1 digest (incorrect length)")
    }
}

impl TryFrom<Tag> for HmacSha1 {
    type Error = Sha1Error;
    fn try_from(digest: Tag) -> Result<Self, Self::Error> {
        digest
            .as_ref()
            .try_into()
            .map_err(|_| Sha1Error {})
            .map(Self)
    }
}

/// Low-level HMAC-SHA1 function.
///
/// # Stability
///
/// This function is *not* considered a part of this crate's public API and is subject to change
/// or disappear entirely in any future updates.
pub fn hmac_sha1(key: &[u8], counter: u64) -> HmacSha1 {
    let key = HmacKey::new(HMAC_SHA1, key);
    sign(&key, &counter.to_be_bytes()).try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Token;

    #[test]
    fn test_example_section_5_4() {
        let digest: HmacSha1 = [
            0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19,
            0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a,
        ]
        .into();
        assert_eq!(digest.truncate::<9>(), Token::<9>(357872921));
        assert_eq!(digest.truncate::<6>(), Token::<6>(872921));
    }
}
