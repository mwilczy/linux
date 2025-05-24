// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Samsung Electronics Co., Ltd.
// Author: Michal Wilczynski <m.wilczynski@samsung.com>

//! Rust T-HEAD TH1520 PWM driver
//!
//! Limitations:
//! - The period and duty cycle are controlled by 32-bit hardware registers,
//!   limiting the maximum resolution.
//! - The driver supports continuous output mode only; one-shot mode is not
//!   implemented.
//! - The controller hardware provides up to 6 PWM channels.
//!

use core::ops::Deref;
use kernel::{
    c_str,
    clk::Clk,
    device::{Bound, Core, Device},
    devres,
    io::mem::IoMem,
    of, platform,
    prelude::*,
    pwm, time,
};

const MAX_PWM_NUM: u32 = 6;

// Register offsets
const fn th1520_pwm_chn_base(n: u32) -> usize {
    (n * 0x20) as usize
}

const fn th1520_pwm_ctrl(n: u32) -> usize {
    th1520_pwm_chn_base(n)
}

const fn th1520_pwm_per(n: u32) -> usize {
    th1520_pwm_chn_base(n) + 0x08
}

const fn th1520_pwm_fp(n: u32) -> usize {
    th1520_pwm_chn_base(n) + 0x0c
}

// Control register bits
const PWM_START: u32 = 1 << 0;
const PWM_CFG_UPDATE: u32 = 1 << 2;
const PWM_CONTINUOUS_MODE: u32 = 1 << 5;
const PWM_FPOUT: u32 = 1 << 8;

const TH1520_PWM_REG_SIZE: usize = 0xB0;

fn ns_to_cycles(ns: u64, rate_hz: u64) -> u64 {
    const NSEC_PER_SEC_U64: u64 = time::NSEC_PER_SEC as u64;

    match ns.checked_mul(rate_hz) {
        Some(product) => product / NSEC_PER_SEC_U64,
        None => u64::MAX,
    }
}

fn cycles_to_ns(cycles: u64, rate_hz: u64) -> u64 {
    const NSEC_PER_SEC_U64: u64 = time::NSEC_PER_SEC as u64;

    // Round up
    let Some(numerator) = cycles
        .checked_mul(NSEC_PER_SEC_U64)
        .and_then(|p| p.checked_add(rate_hz - 1))
    else {
        return u64::MAX;
    };

    numerator / rate_hz
}

/// Hardware-specific waveform representation for TH1520.
#[derive(Copy, Clone, Debug, Default)]
struct Th1520WfHw {
    period_cycles: u32,
    duty_cycles: u32,
    ctrl_val: u32,
    enabled: bool,
}

/// The driver's private data struct. It holds all necessary devres managed resources.
struct Th1520PwmDriverData {
    iomem: devres::Devres<IoMem<TH1520_PWM_REG_SIZE>>,
    clk: Clk,
}

impl pwm::PwmOps for Th1520PwmDriverData {
    type WfHw = Th1520WfHw;

    fn round_waveform_tohw(
        chip: &pwm::Chip,
        _pwm: &pwm::Device,
        wf: &pwm::Waveform,
    ) -> Result<(c_int, Self::WfHw)> {
        let data: &Self = chip.drvdata();

        if wf.period_length_ns == 0 {
            return Ok((
                0,
                Th1520WfHw {
                    enabled: false,
                    ..Default::default()
                },
            ));
        }

        let rate_hz = data.clk.rate().as_hz() as u64;

        let period_cycles = ns_to_cycles(wf.period_length_ns, rate_hz).min(u32::MAX as u64);
        let mut duty_cycles = ns_to_cycles(wf.duty_length_ns, rate_hz).min(u32::MAX as u64);

        let mut ctrl_val = PWM_CONTINUOUS_MODE;

        if wf.duty_offset_ns == 0 {
            ctrl_val |= PWM_FPOUT;
        } else {
            duty_cycles = period_cycles - duty_cycles;
        }

        let wfhw = Th1520WfHw {
            period_cycles: period_cycles as u32,
            duty_cycles: duty_cycles as u32,
            ctrl_val,
            enabled: true,
        };

        dev_dbg!(
            chip.device(),
            "Requested: period {}ns, duty {}ns, offset {}ns -> HW: period {} cyc, duty {} cyc, ctrl 0x{:x}\n",
            wf.period_length_ns,
            wf.duty_length_ns,
            wf.duty_offset_ns,
            wfhw.period_cycles,
            wfhw.duty_cycles,
            wfhw.ctrl_val
        );

        Ok((0, wfhw))
    }

    fn round_waveform_fromhw(
        chip: &pwm::Chip,
        _pwm: &pwm::Device,
        wfhw: &Self::WfHw,
        wf: &mut pwm::Waveform,
    ) -> Result<c_int> {
        let data: &Self = chip.drvdata();
        let rate_hz = data.clk.rate().as_hz() as u64;

        wf.period_length_ns = cycles_to_ns(wfhw.period_cycles as u64, rate_hz);

        let duty_cycles = wfhw.duty_cycles as u64;

        if (wfhw.ctrl_val & PWM_FPOUT) != 0 {
            wf.duty_length_ns = cycles_to_ns(duty_cycles, rate_hz);
            wf.duty_offset_ns = 0;
        } else {
            let period_cycles = wfhw.period_cycles as u64;
            let original_duty_cycles = period_cycles.saturating_sub(duty_cycles);

            wf.duty_length_ns = cycles_to_ns(original_duty_cycles, rate_hz);
            // We can't recover the original non-zero offset, so we just set it
            // to a representative non-zero value.
            wf.duty_offset_ns = 1;
        }

        Ok(0)
    }

    fn read_waveform(
        chip: &pwm::Chip,
        pwm: &pwm::Device,
        parent_dev: &Device<Bound>,
    ) -> Result<Self::WfHw> {
        let data: &Self = chip.drvdata();
        let hwpwm = pwm.hwpwm();
        let iomem_accessor = data.iomem.access(parent_dev)?;
        let iomap = iomem_accessor.deref();

        let ctrl = iomap.try_read32(th1520_pwm_ctrl(hwpwm))?;
        let period_cycles = iomap.try_read32(th1520_pwm_per(hwpwm))?;
        let duty_cycles = iomap.try_read32(th1520_pwm_fp(hwpwm))?;

        let wfhw = Th1520WfHw {
            period_cycles,
            duty_cycles,
            ctrl_val: ctrl,
            enabled: duty_cycles != 0,
        };

        dev_dbg!(
            chip.device(),
            "PWM-{}: read_waveform: Read hw state - period: {}, duty: {}, ctrl: 0x{:x}, enabled: {}",
            hwpwm,
            wfhw.period_cycles,
            wfhw.duty_cycles,
            wfhw.ctrl_val,
            wfhw.enabled
        );

        Ok(wfhw)
    }

    fn write_waveform(
        chip: &pwm::Chip,
        pwm: &pwm::Device,
        wfhw: &Self::WfHw,
        parent_dev: &Device<Bound>,
    ) -> Result {
        let data: &Self = chip.drvdata();
        let hwpwm = pwm.hwpwm();
        let iomem_accessor = data.iomem.access(parent_dev)?;
        let iomap = iomem_accessor.deref();
        let was_enabled = pwm.state().enabled();

        if !wfhw.enabled {
            if was_enabled {
                iomap.try_write32(wfhw.ctrl_val, th1520_pwm_ctrl(hwpwm))?;
                iomap.try_write32(0, th1520_pwm_fp(hwpwm))?;
                iomap.try_write32(wfhw.ctrl_val | PWM_CFG_UPDATE, th1520_pwm_ctrl(hwpwm))?;
            }
            return Ok(());
        }

        iomap.try_write32(wfhw.ctrl_val, th1520_pwm_ctrl(hwpwm))?;
        iomap.try_write32(wfhw.period_cycles, th1520_pwm_per(hwpwm))?;
        iomap.try_write32(wfhw.duty_cycles, th1520_pwm_fp(hwpwm))?;
        iomap.try_write32(wfhw.ctrl_val | PWM_CFG_UPDATE, th1520_pwm_ctrl(hwpwm))?;

        // The `PWM_START` bit must be written in a separate, final transaction, and
        // only when enabling the channel from a disabled state.
        if !was_enabled {
            iomap.try_write32(wfhw.ctrl_val | PWM_START, th1520_pwm_ctrl(hwpwm))?;
        }

        dev_dbg!(
            chip.device(),
            "PWM-{}: Wrote (per: {}, duty: {})",
            hwpwm,
            wfhw.period_cycles,
            wfhw.duty_cycles,
        );

        Ok(())
    }
}

impl Drop for Th1520PwmDriverData {
    fn drop(&mut self) {
        self.clk.disable_unprepare();
    }
}

static TH1520_PWM_OPS: pwm::PwmOpsVTable = pwm::create_pwm_ops::<Th1520PwmDriverData>();

struct Th1520PwmPlatformDriver;

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    <Th1520PwmPlatformDriver as platform::Driver>::IdInfo,
    [(of::DeviceId::new(c_str!("thead,th1520-pwm")), ())]
);

impl platform::Driver for Th1520PwmPlatformDriver {
    type IdInfo = ();
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn probe(
        pdev: &platform::Device<Core>,
        _id_info: Option<&Self::IdInfo>,
    ) -> Result<Pin<KBox<Self>>> {
        let dev = pdev.as_ref();
        let resource = pdev.resource(0).ok_or(ENODEV)?;
        let iomem = pdev.ioremap_resource_sized::<TH1520_PWM_REG_SIZE>(resource)?;
        let clk = Clk::get(pdev.as_ref(), None)?;

        clk.prepare_enable()?;

        // TODO: Get exclusive ownership of the clock to prevent rate changes.
        // The Rust equivalent of `clk_rate_exclusive_get()` is not yet available.
        // This should be updated once it is implemented.
        let rate_hz = clk.rate().as_hz();
        if rate_hz == 0 {
            dev_err!(dev, "Clock rate is zero\n");
            return Err(EINVAL);
        }

        if rate_hz > time::NSEC_PER_SEC as usize {
            dev_err!(
                dev,
                "Clock rate {} Hz is too high, not supported.\n",
                rate_hz
            );
            return Err(ERANGE);
        }

        let drvdata = KBox::new(Th1520PwmDriverData { iomem, clk }, GFP_KERNEL)?;
        let chip = pwm::Chip::new(dev, MAX_PWM_NUM, 0, drvdata)?;

        pwm::Registration::new_foreign_owned(dev, chip, &TH1520_PWM_OPS)?;

        Ok(KBox::new(Th1520PwmPlatformDriver, GFP_KERNEL)?.into())
    }
}

kernel::module_platform_driver! {
    type: Th1520PwmPlatformDriver,
    name: "pwm-th1520",
    authors: ["Michal Wilczynski <m.wilczynski@samsung.com>"],
    description: "T-HEAD TH1520 PWM driver",
    license: "GPL v2",
}
