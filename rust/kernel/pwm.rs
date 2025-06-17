// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Samsung Electronics Co., Ltd.
// Author: Michal Wilczynski <m.wilczynski@samsung.com>

//! PWM subsystem abstractions.
//!
//! C header: [`include/linux/pwm.h`](srctree/include/linux/pwm.h).

use crate::{
    bindings, device,
    error::{self, to_result},
    prelude::*,
    types::{ARef, AlwaysRefCounted, ForeignOwnable, Opaque},
};
use core::{convert::TryFrom, ptr::NonNull};

/// PWM polarity. Mirrors [`enum pwm_polarity`](srctree/include/linux/pwm.h).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Polarity {
    /// Normal polarity (duty cycle defines the high period of the signal).
    Normal,

    /// Inversed polarity (duty cycle defines the low period of the signal).
    Inversed,
}

impl TryFrom<bindings::pwm_polarity> for Polarity {
    type Error = Error;

    fn try_from(polarity: bindings::pwm_polarity) -> Result<Self, Error> {
        match polarity {
            bindings::pwm_polarity_PWM_POLARITY_NORMAL => Ok(Polarity::Normal),
            bindings::pwm_polarity_PWM_POLARITY_INVERSED => Ok(Polarity::Inversed),
            _ => Err(EINVAL),
        }
    }
}

impl From<Polarity> for bindings::pwm_polarity {
    fn from(polarity: Polarity) -> Self {
        match polarity {
            Polarity::Normal => bindings::pwm_polarity_PWM_POLARITY_NORMAL,
            Polarity::Inversed => bindings::pwm_polarity_PWM_POLARITY_INVERSED,
        }
    }
}

/// Represents a PWM waveform configuration.
/// Mirrors struct [`struct pwm_waveform`](srctree/include/linux/pwm.h).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Waveform {
    /// Total duration of one complete PWM cycle, in nanoseconds.
    pub period_length_ns: u64,

    /// Duty-cycle active time, in nanoseconds.
    ///
    /// For a typical normal polarity configuration (active-high) this is the
    /// high time of the signal.
    pub duty_length_ns: u64,

    /// Duty-cycle start offset, in nanoseconds.
    ///
    /// Delay from the beginning of the period to the first active edge.
    /// In most simple PWM setups this is `0`, so the duty cycle starts
    /// immediately at each period’s start.
    pub duty_offset_ns: u64,
}

impl From<bindings::pwm_waveform> for Waveform {
    fn from(wf: bindings::pwm_waveform) -> Self {
        Waveform {
            period_length_ns: wf.period_length_ns,
            duty_length_ns: wf.duty_length_ns,
            duty_offset_ns: wf.duty_offset_ns,
        }
    }
}

impl From<Waveform> for bindings::pwm_waveform {
    fn from(wf: Waveform) -> Self {
        bindings::pwm_waveform {
            period_length_ns: wf.period_length_ns,
            duty_length_ns: wf.duty_length_ns,
            duty_offset_ns: wf.duty_offset_ns,
        }
    }
}

/// Wrapper for board-dependent PWM arguments [`struct pwm_args`](srctree/include/linux/pwm.h).
#[repr(transparent)]
pub struct Args(Opaque<bindings::pwm_args>);

impl Args {
    /// Creates an `Args` wrapper from a C struct pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `c_args_ptr` is a valid, non-null pointer
    /// to `bindings::pwm_args` and that the pointed-to data is valid
    /// for the duration of this function call (as data is copied).
    unsafe fn from_c_ptr(c_args_ptr: *const bindings::pwm_args) -> Self {
        // SAFETY: Caller guarantees `c_args_ptr` is valid. We dereference it to copy.
        Args(Opaque::new(unsafe { *c_args_ptr }))
    }

    /// Returns the period of the PWM signal in nanoseconds.
    pub fn period(&self) -> u64 {
        // SAFETY: `self.0.get()` returns a pointer to the `bindings::pwm_args`
        // managed by the `Opaque` wrapper. This pointer is guaranteed to be
        // valid and aligned for the lifetime of `self` because `Opaque` owns a copy.
        unsafe { (*self.0.get()).period }
    }

    /// Returns the polarity of the PWM signal.
    pub fn polarity(&self) -> Result<Polarity, Error> {
        // SAFETY: `self.0.get()` returns a pointer to the `bindings::pwm_args`
        // managed by the `Opaque` wrapper. This pointer is guaranteed to be
        // valid and aligned for the lifetime of `self`.
        let raw_polarity = unsafe { (*self.0.get()).polarity };
        Polarity::try_from(raw_polarity)
    }
}

/// Wrapper for PWM state [`struct pwm_state`](srctree/include/linux/pwm.h).
#[repr(transparent)]
pub struct State(bindings::pwm_state);

impl State {
    /// Creates a `State` wrapper by taking ownership of a C `pwm_state` value.
    pub(crate) fn from_c(c_state: bindings::pwm_state) -> Self {
        State(c_state)
    }

    /// Returns `true` if the PWM signal is enabled.
    pub fn enabled(&self) -> bool {
        self.0.enabled
    }
}

/// Describes the outcome of a `round_waveform` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingOutcome {
    /// The requested waveform was achievable exactly or by rounding values down.
    ExactOrRoundedDown,

    /// The requested waveform could only be achieved by rounding up.
    RoundedUp,
}

/// Wrapper for a PWM device [`struct pwm_device`](srctree/include/linux/pwm.h).
#[repr(transparent)]
pub struct Device(Opaque<bindings::pwm_device>);

impl Device {
    /// Creates a reference to a [`Device`] from a valid C pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`Device`] reference.
    pub(crate) unsafe fn as_ref<'a>(ptr: *mut bindings::pwm_device) -> &'a Self {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `Device` type being transparent makes the cast ok.
        unsafe { &*ptr.cast::<Self>() }
    }

    /// Returns a raw pointer to the underlying `pwm_device`.
    fn as_raw(&self) -> *mut bindings::pwm_device {
        self.0.get()
    }

    /// Gets the hardware PWM index for this device within its chip.
    pub fn hwpwm(&self) -> u32 {
        // SAFETY: `self.as_raw()` provides a valid pointer for `self`'s lifetime.
        unsafe { (*self.as_raw()).hwpwm }
    }

    /// Gets a reference to the parent `Chip` that this device belongs to.
    pub fn chip(&self) -> &Chip {
        // SAFETY: `self.as_raw()` provides a valid pointer. (*self.as_raw()).chip
        // is assumed to be a valid pointer to `pwm_chip` managed by the kernel.
        // Chip::as_ref's safety conditions must be met.
        unsafe { Chip::as_ref((*self.as_raw()).chip) }
    }

    /// Gets the label for this PWM device, if any.
    pub fn label(&self) -> Option<&CStr> {
        // SAFETY: self.as_raw() provides a valid pointer.
        let label_ptr = unsafe { (*self.as_raw()).label };
        if label_ptr.is_null() {
            None
        } else {
            // SAFETY: label_ptr is non-null and points to a C string
            // managed by the kernel, valid for the lifetime of the PWM device.
            Some(unsafe { CStr::from_char_ptr(label_ptr) })
        }
    }

    /// Gets a copy of the board-dependent arguments for this PWM device.
    pub fn args(&self) -> Args {
        // SAFETY: self.as_raw() gives a valid pointer to `pwm_device`.
        // The `args` field is a valid `pwm_args` struct embedded within `pwm_device`.
        // `Args::from_c_ptr`'s safety conditions are met by providing this pointer.
        unsafe { Args::from_c_ptr(&(*self.as_raw()).args) }
    }

    /// Gets a copy of the current state of this PWM device.
    pub fn state(&self) -> State {
        // SAFETY: `self.as_raw()` gives a valid pointer. `(*self.as_raw()).state`
        // is a valid `pwm_state` struct. `State::from_c` copies this data.
        State::from_c(unsafe { (*self.as_raw()).state })
    }

    /// Sets the PWM waveform configuration and enables the PWM signal.
    pub fn set_waveform(&self, wf: &Waveform, exact: bool) -> Result {
        let c_wf = bindings::pwm_waveform::from(*wf);

        // SAFETY: `self.as_raw()` provides a valid `*mut pwm_device` pointer.
        // `&c_wf` is a valid pointer to a `pwm_waveform` struct. The C function
        // handles all necessary internal locking.
        let ret = unsafe { bindings::pwm_set_waveform_might_sleep(self.as_raw(), &c_wf, exact) };
        to_result(ret)
    }

    /// Queries the hardware for the configuration it would apply for a given
    /// request.
    pub fn round_waveform(&self, wf: &mut Waveform) -> Result<RoundingOutcome> {
        let mut c_wf = bindings::pwm_waveform::from(*wf);

        // SAFETY: `self.as_raw()` provides a valid `*mut pwm_device` pointer.
        // `&mut c_wf` is a valid pointer to a mutable `pwm_waveform` struct that
        // the C function will update.
        let ret = unsafe { bindings::pwm_round_waveform_might_sleep(self.as_raw(), &mut c_wf) };

        to_result(ret)?;

        *wf = Waveform::from(c_wf);

        if ret == 1 {
            Ok(RoundingOutcome::RoundedUp)
        } else {
            Ok(RoundingOutcome::ExactOrRoundedDown)
        }
    }

    /// Reads the current waveform configuration directly from the hardware.
    pub fn get_waveform(&self) -> Result<Waveform> {
        let mut c_wf = bindings::pwm_waveform::default();

        // SAFETY: `self.as_raw()` is a valid pointer. We provide a valid pointer
        // to a stack-allocated `pwm_waveform` struct for the kernel to fill.
        let ret = unsafe { bindings::pwm_get_waveform_might_sleep(self.as_raw(), &mut c_wf) };

        to_result(ret)?;

        Ok(Waveform::from(c_wf))
    }
}

/// Wrapper for a PWM chip/controller ([`struct pwm_chip`](srctree/include/linux/pwm.h)).
#[repr(transparent)]
pub struct Chip(Opaque<bindings::pwm_chip>);

impl Chip {
    /// Creates a reference to a [`Chip`] from a valid pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`Chip`] reference.
    pub(crate) unsafe fn as_ref<'a>(ptr: *mut bindings::pwm_chip) -> &'a Self {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `Chip` type being transparent makes the cast ok.
        unsafe { &*ptr.cast::<Self>() }
    }

    /// Returns a raw pointer to the underlying `pwm_chip`.
    pub(crate) fn as_raw(&self) -> *mut bindings::pwm_chip {
        self.0.get()
    }

    /// Gets the number of PWM channels (hardware PWMs) on this chip.
    pub fn npwm(&self) -> u32 {
        // SAFETY: `self.as_raw()` provides a valid pointer for `self`'s lifetime.
        unsafe { (*self.as_raw()).npwm }
    }

    /// Returns `true` if the chip supports atomic operations for configuration.
    pub fn is_atomic(&self) -> bool {
        // SAFETY: `self.as_raw()` provides a valid pointer for `self`'s lifetime.
        unsafe { (*self.as_raw()).atomic }
    }

    /// Returns a reference to the embedded `struct device` abstraction.
    pub fn device(&self) -> &device::Device {
        // SAFETY: `self.as_raw()` provides a valid pointer to `bindings::pwm_chip`.
        // The `dev` field is an instance of `bindings::device` embedded within `pwm_chip`.
        // Taking a pointer to this embedded field is valid.
        // `device::Device` is `#[repr(transparent)]`.
        // The lifetime of the returned reference is tied to `self`.
        let dev_field_ptr = unsafe { core::ptr::addr_of!((*self.as_raw()).dev) };
        // SAFETY: `dev_field_ptr` is a valid pointer to `bindings::device`.
        // Casting and dereferencing is safe due to `repr(transparent)` and lifetime.
        unsafe { &*(dev_field_ptr.cast::<device::Device>()) }
    }

    /// Gets the *typed* driver-specific data associated with this chip's embedded device.
    pub fn drvdata<T: 'static>(&self) -> &T {
        // SAFETY: `self.as_raw()` gives a valid pwm_chip pointer.
        // `bindings::pwmchip_get_drvdata` is the C function to retrieve driver data.
        let ptr = unsafe { bindings::pwmchip_get_drvdata(self.as_raw()) };

        // SAFETY: The only way to create a chip is through Chip::new, which initializes
        // this pointer.
        unsafe { &*ptr.cast::<T>() }
    }

    /// Allocates and wraps a PWM chip using `bindings::pwmchip_alloc`.
    ///
    /// Returns an [`ARef<Chip>`] managing the chip's lifetime via refcounting
    /// on its embedded `struct device`.
    pub fn new<T: 'static + ForeignOwnable>(
        parent_dev: &device::Device,
        npwm: u32,
        sizeof_priv: usize,
        drvdata: T,
    ) -> Result<ARef<Self>> {
        // SAFETY: `parent_device_for_dev_field.as_raw()` is valid.
        // `bindings::pwmchip_alloc` returns a valid `*mut bindings::pwm_chip` (refcount 1)
        // or an ERR_PTR.
        let c_chip_ptr_raw =
            unsafe { bindings::pwmchip_alloc(parent_dev.as_raw(), npwm, sizeof_priv) };

        let c_chip_ptr: *mut bindings::pwm_chip = error::from_err_ptr(c_chip_ptr_raw)?;

        // Cast the `*mut bindings::pwm_chip` to `*mut Chip`. This is valid because
        // `Chip` is `repr(transparent)` over `Opaque<bindings::pwm_chip>`, and
        // `Opaque<T>` is `repr(transparent)` over `T`.
        let chip_ptr_as_self = c_chip_ptr.cast::<Self>();

        // SAFETY: The pointer is valid, so we can create a temporary ref to set data.
        let chip_ref = unsafe { &*chip_ptr_as_self };
        // SAFETY: `chip_ref` points to a valid chip from `pwmchip_alloc` and `drvdata` is a valid,
        // owned pointer from `ForeignOwnable` to be stored in the chip's private data.
        unsafe { bindings::pwmchip_set_drvdata(chip_ref.as_raw(), drvdata.into_foreign().cast()) }

        // SAFETY: `chip_ptr_as_self` points to a valid `Chip` (layout-compatible with
        // `bindings::pwm_chip`) whose embedded device has refcount 1.
        // `ARef::from_raw` takes this pointer and manages it via `AlwaysRefCounted`.
        Ok(unsafe { ARef::from_raw(NonNull::new_unchecked(chip_ptr_as_self)) })
    }

    /// Returns a reference to the parent device of this PWM chip's device.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the parent device exists and is bound.
    /// This is guaranteed by the PWM core during `PwmOps` callbacks.
    unsafe fn bound_parent_device(&self) -> &device::Device<Bound> {
        // SAFETY: Per the function's safety contract, the parent device exists.
        let parent = unsafe { self.device().parent().unwrap_unchecked() };

        // SAFETY: Per the function's safety contract, the parent device is bound.
        // The pointer is cast from `&Device` to `&Device<Bound>`.
        unsafe { &*core::ptr::from_ref(parent).cast::<device::Device<Bound>>() }
    }
}

// SAFETY: Implements refcounting for `Chip` using the embedded `struct device`.
unsafe impl AlwaysRefCounted for Chip {
    #[inline]
    fn inc_ref(&self) {
        // SAFETY: `self.0.get()` points to a valid `pwm_chip` because `self` exists.
        // The embedded `dev` is valid. `get_device` increments its refcount.
        unsafe {
            bindings::get_device(core::ptr::addr_of_mut!((*self.0.get()).dev));
        }
    }

    #[inline]
    unsafe fn dec_ref(obj: NonNull<Chip>) {
        let c_chip_ptr = obj.cast::<bindings::pwm_chip>().as_ptr();

        // SAFETY: `obj` is a valid pointer to a `Chip` (and thus `bindings::pwm_chip`)
        // with a non-zero refcount. `put_device` handles decrement and final release.
        unsafe {
            bindings::put_device(core::ptr::addr_of_mut!((*c_chip_ptr).dev));
        }
    }
}

// SAFETY: `Chip` is a wrapper around `*mut bindings::pwm_chip`. The underlying C
// structure's state is managed and synchronized by the kernel's device model
// and PWM core locking mechanisms. Therefore, it is safe to move the `Chip`
// wrapper (and the pointer it contains) across threads.
unsafe impl Send for Chip {}

// SAFETY: It is safe for multiple threads to have shared access (`&Chip`) because
// the `Chip` data is immutable from the Rust side without holding the appropriate
// kernel locks, which the C core is responsible for. Any interior mutability is
// handled and synchronized by the C kernel code.
unsafe impl Sync for Chip {}
