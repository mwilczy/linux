// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Samsung Electronics Co., Ltd.
// Author: Michal Wilczynski <m.wilczynski@samsung.com>

//! PWM subsystem abstractions.
//!
//! C header: [`include/linux/pwm.h`](srctree/include/linux/pwm.h).

use crate::{
    bindings,
    prelude::*,
    types::Opaque,
};
use core::convert::TryFrom;

/// Maximum size for the hardware-specific waveform representation buffer.
///
/// From C: `#define WFHWSIZE 20`
pub const WFHW_MAX_SIZE: usize = 20;

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

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// Creates a new zeroed `State`.
    pub fn new() -> Self {
        State(bindings::pwm_state::default())
    }

    /// Creates a `State` wrapper by taking ownership of a C `pwm_state` value.
    pub(crate) fn from_c(c_state: bindings::pwm_state) -> Self {
        State(c_state)
    }

    /// Gets the period of the PWM signal in nanoseconds.
    pub fn period(&self) -> u64 {
        self.0.period
    }

    /// Sets the period of the PWM signal in nanoseconds.
    pub fn set_period(&mut self, period_ns: u64) {
        self.0.period = period_ns;
    }

    /// Gets the duty cycle of the PWM signal in nanoseconds.
    pub fn duty_cycle(&self) -> u64 {
        self.0.duty_cycle
    }

    /// Sets the duty cycle of the PWM signal in nanoseconds.
    pub fn set_duty_cycle(&mut self, duty_ns: u64) {
        self.0.duty_cycle = duty_ns;
    }

    /// Returns `true` if the PWM signal is enabled.
    pub fn enabled(&self) -> bool {
        self.0.enabled
    }

    /// Sets the enabled state of the PWM signal.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.0.enabled = enabled;
    }

    /// Gets the polarity of the PWM signal.
    pub fn polarity(&self) -> Result<Polarity, Error> {
        Polarity::try_from(self.0.polarity)
    }

    /// Sets the polarity of the PWM signal.
    pub fn set_polarity(&mut self, polarity: Polarity) {
        self.0.polarity = polarity.into();
    }

    /// Returns `true` if the PWM signal is configured for power usage hint.
    pub fn usage_power(&self) -> bool {
        self.0.usage_power
    }

    /// Sets the power usage hint for the PWM signal.
    pub fn set_usage_power(&mut self, usage_power: bool) {
        self.0.usage_power = usage_power;
    }
}
