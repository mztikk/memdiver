//! Addresses in the target process.

use std::fmt;

/// A virtual address in a target process.
///
/// Addresses are stored as `u64` because a 32-bit host may inspect a 64-bit
/// process, and because external memory is not part of this process's address
/// space. Use [`Address::new`] or `From<u64>` to construct one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address(u64);

impl Address {
    /// The null address.
    pub const NULL: Self = Self(0);

    /// Creates an address from its numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric value of the address.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns `true` for the null address.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Adds an offset, returning `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, offset: u64) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Subtracts an offset, returning `None` on underflow.
    #[must_use]
    pub const fn checked_sub(self, offset: u64) -> Option<Self> {
        match self.0.checked_sub(offset) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({:#x})", self.0)
    }
}

impl From<u64> for Address {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<usize> for Address {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

impl From<Address> for u64 {
    fn from(address: Address) -> Self {
        address.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_as_hex() {
        assert_eq!(Address::new(0x1234).to_string(), "0x1234");
        assert_eq!(format!("{:?}", Address::NULL), "Address(0x0)");
    }

    #[test]
    fn converts_from_numeric_types() {
        assert_eq!(Address::from(42u64).get(), 42);
        let value = Address::from(42usize);
        assert_eq!(value.get(), 42);
        assert_eq!(u64::from(value), 42);
        assert!(Address::default().is_null());
    }

    #[test]
    fn checked_arithmetic_reports_overflow() {
        assert_eq!(
            Address::new(0x1000).checked_add(0x10),
            Some(Address::new(0x1010))
        );
        assert_eq!(
            Address::new(0x1000).checked_sub(0x10),
            Some(Address::new(0xff0))
        );
        assert_eq!(Address::new(0x1000).checked_sub(0x1001), None);
        assert_eq!(Address::new(u64::MAX).checked_add(1), None);
    }
}
