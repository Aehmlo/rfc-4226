//! Type-level encoding of HOTP token length restrictions.

mod private {
    /// Marks a trait as being for crate-internal use only.
    pub trait Sealed {}

    impl<const N: u8> Sealed for super::Length<N> {}
}

/// Uninhabited type parameterized by a `const u8` for selective trait implementations.
///
/// This type exists as a target for [the `TokenLength` trait][TokenLength], which encodes
/// allowed HOTP token lengths in the type system.
pub enum Length<const N: u8> {}

/// Marker trait for allowable HOTP token lengths.
///
/// Per [RFC 4226][4226], HOTP tokens MUST be of length at least 6 and possibly of length 7 or 8.
/// Appendix E suggests that 9-digit codes are also allowed. As such, this trait, along with the
/// [`Length`][Length] type, is used to ensure that truncated tokens have 6, 7, 8, or 9 decimal
/// digits.
///
/// [RFC 6328][6328], which describes TOTP, does not explicitly specify allowable numbers of
/// digits. However, the provided sample code supports up to 8 digits, supporting the retention
/// of the 6–9 digit limit from HOTP.
///
/// [4226]: https://datatracker.ietf.org/doc/html/rfc4226
/// [6328]: https://datatracker.ietf.org/doc/html/rfc6238
pub trait TokenLength: private::Sealed {}

impl TokenLength for Length<6> {}
impl TokenLength for Length<7> {}
impl TokenLength for Length<8> {}
// Section E.2 of Appendix E in RFC 4226 indicates that 9-digit codes are allowed
impl TokenLength for Length<9> {}
