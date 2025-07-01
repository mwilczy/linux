// SPDX-License-Identifier: GPL-2.0

//! Generic memory-mapped IO.

use core::ops::Deref;

use crate::device::Device;
use crate::device::Bound;
use crate::devres::Devres;
use crate::{
    alloc::{KBox},
};
use crate::io;
use crate::io::resource::Region;
use crate::io::resource::Resource;
use crate::io::Io;
use crate::io::IoRaw;
use crate::prelude::*;

use core::pin::Pin;

/// An exclusive memory-mapped IO region.
///
/// # Invariants
///
/// - [`ExclusiveIoMem`] has exclusive access to the underlying `iomem`.
pub struct ExclusiveIoMem<const SIZE: usize> {
    /// The region abstraction. This represents exclusive access to the
    /// range represented by the underlying `iomem`.
    ///
    /// It's placed first to ensure that the region is released before it is
    /// unmapped as a result of the drop order.
    ///
    /// This field is needed for ownership of the region.
    _region: Region,
    /// The underlying `IoMem` instance.
    iomem: IoMem<SIZE>,
}

impl<'a, const SIZE: usize> ExclusiveIoMem<SIZE> {
    /// Creates a new `ExclusiveIoMem` instance.
    pub(crate) fn ioremap(resource: &Resource) -> Result<Self> {
        let iomem = IoMem::ioremap(resource)?;

        let start = resource.start();
        let size = resource.size();
        let name = resource.name();

        let region = resource
            .request_region(start, size, name, io::resource::flags::IORESOURCE_MEM)
            .ok_or(EBUSY)?;

        let iomem = ExclusiveIoMem {
            iomem,
            _region: region,
        };

        Ok(iomem)
    }

    pub(crate) fn new(
        resource: &Resource,
        device: &'a Device<Bound>,
    ) -> impl PinInit<Devres<Self>, Error> + 'a {
        let iomem = Self::ioremap(resource);
        Devres::new(device, iomem)
    }
}

impl<const SIZE: usize> Deref for ExclusiveIoMem<SIZE> {
    type Target = Io<SIZE>;

    fn deref(&self) -> &Self::Target {
        &self.iomem
    }
}

/// A generic memory-mapped IO region.
///
/// Accesses to the underlying region is checked either at compile time, if the
/// region's size is known at that point, or at runtime otherwise.
///
/// # Invariants
///
/// `IoMem` always holds an `IoRaw` instance that holds a valid pointer to the
/// start of the I/O memory mapped region.
pub struct IoMem<const SIZE: usize = 0> {
    io: IoRaw<SIZE>,
}

impl<'a, const SIZE: usize> IoMem<SIZE> {
    fn ioremap(resource: &Resource) -> Result<Self> {
        let size = resource.size();
        if size == 0 {
            return Err(EINVAL);
        }

        let res_start = resource.start();

        let addr = if resource
            .flags()
            .contains(io::resource::flags::IORESOURCE_MEM_NONPOSTED)
        {
            // SAFETY:
            // - `res_start` and `size` are read from a presumably valid `struct resource`.
            // - `size` is known not to be zero at this point.
            unsafe { bindings::ioremap_np(res_start, size as usize) }
        } else {
            // SAFETY:
            // - `res_start` and `size` are read from a presumably valid `struct resource`.
            // - `size` is known not to be zero at this point.
            unsafe { bindings::ioremap(res_start, size as usize) }
        };

        if addr.is_null() {
            return Err(ENOMEM);
        }

        let io = IoRaw::new(addr as usize, size as usize)?;
        let io = IoMem { io };

        Ok(io)
    }

    /// Creates a new `IoMem` instance.
    pub(crate) fn new(
        resource: &Resource,
        device: &'a Device<Bound>,
    ) -> impl PinInit<Devres<Self>, Error> + 'a {
        let io = Self::ioremap(resource);
        Devres::new(device, io)
    }}

impl<const SIZE: usize> Drop for IoMem<SIZE> {
    fn drop(&mut self) {
        // SAFETY: Safe as by the invariant of `Io`.
        unsafe { bindings::iounmap(self.io.addr() as *mut core::ffi::c_void) }
    }
}

impl<const SIZE: usize> Deref for IoMem<SIZE> {
    type Target = Io<SIZE>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Safe as by the invariant of `IoMem`.
        unsafe { Io::from_raw(&self.io) }
    }
}
