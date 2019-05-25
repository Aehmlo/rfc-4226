use std::convert::TryInto;

use ring::{
    digest::SHA1,
    hmac::{sign, SigningKey},
};

const MIN_DIGITS: u8 = 6;
const MAX_DIGITS: u8 = 8;
const MIN_SECRET_BYTES: usize = 16;

/// Synchronized moving counter.
///
/// [RFC 4226][4226] describes an "8-byte synchronized moving counter." To allow for more
/// sophisticated forms of counters (including in custom structs, etc.), the `Counter` and
/// [`CounterBytes`][CounterBytes] traits are exposed.
///
/// ## `Counter` vs. [`CounterBytes`][CounterBytes]
///
/// The `Counter` trait has a method with a return type of `u64`, which is a (big-endian) unsigned
/// 8-byte integer. However, it is frequently more convenient to return an array of bytes. For
/// convenience, the [`CounterBytes`][CounterBytes] trait is therefore provided.
/// `CounterBytes` has a method with a return type of `[u8; 8]`, an array of eight bytes. This byte
/// array is simply concatenated (big-endian) to form a `u64`, which is used as the counter value.
///
/// ## Notes
///
/// Due to the strict nature of the specification, only 8 bytes of information may be extracted and
/// used as a counter.
///
/// `Counter` is automatically implemented for `u64`, enabling raw `u64`s to be used as counter
/// values with no additional configuration.
///
/// [4226]: https://tools.ietf.org/html/rfc4226
/// [CounterBytes]: trait.CounterBytes.html
pub trait Counter {
    /// The counter value as an eight-byte, big-endian, unsigned integer.
    fn value(&self) -> u64;
}

/// Raw synchronized moving counter.
///
/// See the documentation for [`Counter`][Counter] for more information.
///
/// [Counter]: trait.Counter.html
pub trait CounterBytes {
    /// The counter value as an array of bytes.
    fn value(&self) -> [u8; 8];
}

impl CounterBytes for [u8; 8] {
    fn value(&self) -> [u8; 8] {
        *self
    }
}

impl<T: CounterBytes> Counter for T {
    fn value(&self) -> u64 {
        u64::from_be_bytes(CounterBytes::value(self))
    }
}

impl Counter for u64 {
    fn value(&self) -> u64 {
        *self
    }
}

/// Shared secret.
///
/// As per [RFC 4226][4226], "each HOTP generator has a different and unique secret."
///
/// This trait enables abstraction over different types of secret. All secrets must be coerced to a
/// byte string for hashing, so secrets must implement `AsRef<[u8]>`. This trait is implemented for
/// `[u8; n]` for 16 ≤ n ≤ 32, drawing inspiration from `libcore`. It is also implemented for
/// `&str` and `String`. Thus, any of these types may be used as secrets with no additional
/// configuration.
///
/// # Requirements
///
/// As per [RFC 4226][4226], the secret MUST be at least 128 bits (with a recommended length of 160
/// bits). If the secret is not at least this long, the functions in this crate will return errors.
///
/// [4226]: https://tools.ietf.org/html/rfc4226
pub trait Secret: AsRef<[u8]> {}
impl Secret for String {}
impl Secret for &'_ str {}
impl Secret for &'_ [u8] {}

macro_rules! impl_secret_array_slice {
    ($x:literal, $($y:literal),+) => (
        impl_secret_array_slice!($x);
        impl_secret_array_slice!($($y),+);
    );
    ($x:literal) => (impl Secret for &'_ [u8; $x] {})
}
impl_secret_array_slice!(16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);

/// HOTP error type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HotpError {
    /// The hash calculated internally was incorrectly formed (incorrect length).
    Hash,
    /// The provided secret was smaller than 20 bytes.
    Secret,
    /// The requested number of digits was outside of the range [6, 8].
    Digits,
}

impl From<std::array::TryFromSliceError> for HotpError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        HotpError::Hash
    }
}

pub type Result<T> = std::result::Result<T, HotpError>;

// "Dynamic truncation" (https://tools.ietf.org/html/rfc4226#section-5.3)
fn truncate(hs: &[u8]) -> Result<u32> {
    let hs: [u8; 20] = hs.try_into()?;
    let last = hs[19];
    // Get the offset location from the last 4 bits of the hash
    let offset = (last & 0xf) as usize;
    let o = offset;
    // Strip the leading bit and return 31 bits in a u32 (big-endian)
    Ok(u32::from_be_bytes([hs[o], hs[o + 1], hs[o + 2], hs[o + 3]]) & 0x7fff_ffff)
}

/// Computes the "raw" HOTP value for the given secret and counter.
///
/// No truncation of digits is performed in this function; for a truncating version, see
/// [`hotp`][hotp].
///
/// # Errors
///
/// This function will return an error if the given key resolves to fewer than 128 bits.
///
/// [hotp]: fn.hotp.html
pub fn raw_hotp<S: Secret, C: Counter>(secret: S, counter: C) -> Result<u32> {
    let c = counter.value().to_be_bytes();
    let k: &[u8] = secret.as_ref();
    if k.len() < MIN_SECRET_BYTES {
        return Err(HotpError::Secret);
    }
    let key = SigningKey::new(&SHA1, &k);
    let hs = sign(&key, &c);
    truncate(hs.as_ref())
}

/// Computes an HOTP code of the desired length given a secret and counter value.
///
/// Unlike [`raw_hotp`][raw_hotp], this function truncates the computed value to a given length.
///
/// # Errors
/// This function will return an error if the given key resolves to fewer than 128 bits or if `!((6..=8).contains(digits))`.
///
/// [raw_hotp]: fn.raw_hotp.html
pub fn hotp<S: Secret, C: Counter>(secret: S, counter: C, digits: u8) -> Result<u32> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(HotpError::Digits);
    }
    raw_hotp(secret, counter).map(|x| x % 10_u32.pow(digits.into()))
}

mod provider {
    type Throttle = u8; // Throttling parameter (attempts)
    type Resync = u8; // Resynchronization parameter

    /// Encodes an error encountered while attempting to authenticate with a provider.
    pub enum Error {
        /// The retry threshold has been reached.
        MaximumRetries,
        /// The given token was of incorrect length.
        InvalidTokenLength,
    }

    struct Handle {
        attempts: u8,
        remaining: u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncate_19_bytes() {
        let hs = [0; 19];
        assert_eq!(truncate(&hs), Err(HotpError::Hash));
    }
    #[test]
    fn truncate_0_bytes() {
        let hs = [];
        assert_eq!(truncate(&hs), Err(HotpError::Hash));
    }
    #[test]
    fn truncate_21_bytes() {
        let hs = [0; 21];
        assert_eq!(truncate(&hs), Err(HotpError::Hash));
    }
    #[test]
    fn truncate_20_bytes() {
        let hs = [0; 20];
        assert_eq!(truncate(&hs), Ok(0));
    }
    #[test]
    fn raw_hotp_short_secret() {
        let secret = "1234"; // Note: b"1234" fails to compile
        assert_eq!(raw_hotp(secret, 0), Err(HotpError::Secret));
    }
    #[test]
    fn test_raw_hotp() {
        let secret = b"12345678901234567890";
        assert_eq!(raw_hotp(secret, 0), Ok(0x4c93cf18));
        assert_eq!(raw_hotp(secret, 1), Ok(0x41397eea));
        assert_eq!(raw_hotp(secret, 2), Ok(0x82fef30));
        assert_eq!(raw_hotp(secret, 3), Ok(0x66ef7655));
        assert_eq!(raw_hotp(secret, 4), Ok(0x61c5938a));
        assert_eq!(raw_hotp(secret, 5), Ok(0x33c083d4));
        assert_eq!(raw_hotp(secret, 6), Ok(0x7256c032));
        assert_eq!(raw_hotp(secret, 7), Ok(0x4e5b397));
        assert_eq!(raw_hotp(secret, 8), Ok(0x2823443f));
        assert_eq!(raw_hotp(secret, 9), Ok(0x2679dc69));
    }
    #[test]
    fn test_hotp() {
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 0, 6), Ok(755224));
        assert_eq!(hotp(secret, 1, 6), Ok(287082));
        assert_eq!(hotp(secret, 2, 6), Ok(359152));
        assert_eq!(hotp(secret, 3, 6), Ok(969429));
        assert_eq!(hotp(secret, 4, 6), Ok(338314));
        assert_eq!(hotp(secret, 5, 6), Ok(254676));
        assert_eq!(hotp(secret, 6, 6), Ok(287922));
        assert_eq!(hotp(secret, 7, 6), Ok(162583));
        assert_eq!(hotp(secret, 8, 6), Ok(399871));
        assert_eq!(hotp(secret, 9, 6), Ok(520489));
    }
}
