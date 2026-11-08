//! Pointer-width detection and pointer-chain resolution.

use memdiver_sys::PointerWidth;

use crate::{Address, Error, Process, Result};

impl Process {
    /// Returns the pointer width of the target process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Query`] when the platform cannot determine the target's
    /// bitness.
    pub fn pointer_width(&self) -> Result<PointerWidth> {
        self.inner.pointer_width().map_err(|source| Error::Query {
            pid: self.pid,
            what: "pointer width",
            source,
        })
    }

    /// Reads a pointer of the given width from `address`.
    ///
    /// # Errors
    ///
    /// Returns the same read errors as [`Process::read_value`].
    pub fn read_pointer(&self, address: Address, width: PointerWidth) -> Result<Address> {
        match width {
            PointerWidth::Bits32 => {
                let value: u32 = self.read_value(address)?;
                Ok(Address::new(u64::from(value)))
            }
            PointerWidth::Bits64 => self.read_value::<u64>(address).map(Address::new),
        }
    }

    /// Resolves a pointer chain.
    ///
    /// `base` is the address of the first pointer slot. For each offset, the
    /// pointer at the current address is read and the offset is added; the last
    /// offset is therefore the final displacement, not another dereference.
    /// An empty slice returns `base` unchanged.
    ///
    /// For example, with `base = module + 0x100` and offsets `[0x10, 0x20]`, the
    /// result is `read_pointer(read_pointer(base) + 0x10) + 0x20`.
    ///
    /// # Errors
    ///
    /// Returns read errors for unreadable slots and
    /// [`Error::PointerChainOverflow`] when an addition exceeds the target's
    /// pointer width.
    pub fn resolve_pointer_chain(
        &self,
        base: Address,
        offsets: &[u64],
        width: PointerWidth,
    ) -> Result<Address> {
        let mut current = base;
        for offset in offsets {
            let pointer = self.read_pointer(current, width)?;
            current = checked_pointer_add(width, pointer, *offset).ok_or(
                Error::PointerChainOverflow {
                    pid: self.pid,
                    address: pointer,
                    offset: *offset,
                },
            )?;
        }
        Ok(current)
    }
}

fn checked_pointer_add(width: PointerWidth, pointer: Address, offset: u64) -> Option<Address> {
    let limit = match width {
        PointerWidth::Bits32 => u64::from(u32::MAX),
        PointerWidth::Bits64 => u64::MAX,
    };
    pointer
        .get()
        .checked_add(offset)
        .filter(|value| *value <= limit)
        .map(Address::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_width_bytes() {
        assert_eq!(PointerWidth::Bits32.bytes(), 4);
        assert_eq!(PointerWidth::Bits64.bytes(), 8);
    }

    #[test]
    fn pointer_addition_respects_target_width() {
        assert_eq!(
            checked_pointer_add(PointerWidth::Bits32, Address::new(u64::from(u32::MAX)), 0),
            Some(Address::new(u64::from(u32::MAX)))
        );
        assert_eq!(
            checked_pointer_add(PointerWidth::Bits32, Address::new(u64::from(u32::MAX)), 1),
            None
        );
        assert_eq!(
            checked_pointer_add(PointerWidth::Bits64, Address::new(u64::MAX), 1),
            None
        );
        assert_eq!(
            checked_pointer_add(PointerWidth::Bits64, Address::new(0x1000), 0x20),
            Some(Address::new(0x1020))
        );
    }
}
