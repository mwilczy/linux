// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Samsung Electronics Co., Ltd.
// Author: Michal Wilczynski <m.wilczynski@samsung.com>

//! Rust T-HEAD TH1520 PWM driver

use core::ops::Deref;
use kernel::{
    c_str,
    clk::Clk,
    device::{Bound, Core, Device},
    devres,
    error::{code::*, Result},
    io::mem::IoMem,
    math::KernelMathExt,
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

/// Hardware-specific waveform representation for TH1520.
#[derive(Copy, Clone, Debug, Default)]
struct Th1520WfHw {
    period_cycles: u32,
    duty_cycles: u32,
    ctrl_val: u32,
    enabled: bool,
}

/// The driver's private data struct. It holds all necessary devres-managed resources.
struct Th1520PwmDriverData {
    iomem: devres::Devres<IoMem<TH1520_PWM_REG_SIZE>>,
    clk: Clk,
}

impl pwm::PwmOps for Th1520PwmDriverData {
    type WfHw = Th1520WfHw;

    fn get_state(
        chip: &mut pwm::Chip,
        pwm: &mut pwm::Device,
        state: &mut pwm::State,
        parent_dev: &Device<Bound>,
    ) -> Result {
        let data: &Self = chip.drvdata().ok_or(EINVAL)?;
        let hwpwm = pwm.hwpwm();
        let iomem_guard = data.iomem.access(parent_dev)?;
        let iomap = iomem_guard.deref();
        let ctrl = iomap.read32(th1520_pwm_ctrl(hwpwm));
        let period_cycles = iomap.read32(th1520_pwm_per(hwpwm));
        let duty_cycles = iomap.read32(th1520_pwm_fp(hwpwm));

        state.set_enabled(duty_cycles != 0);

        let rate_hz = data.clk.rate().as_hz();
        let period_ns = (period_cycles as u64)
            .mul_div(time::NSEC_PER_SEC as u64, rate_hz as u64)
            .unwrap_or(0);
        state.set_period(period_ns);

        let duty_ns = (duty_cycles as u64)
            .mul_div(time::NSEC_PER_SEC as u64, rate_hz as u64)
            .unwrap_or(0);
        state.set_duty_cycle(duty_ns);

        if (ctrl & PWM_FPOUT) != 0 {
            state.set_polarity(pwm::Polarity::Normal);
        } else {
            state.set_polarity(pwm::Polarity::Inversed);
        }

        Ok(())
    }

    fn round_waveform_tohw(
        chip: &mut pwm::Chip,
        pwm: &mut pwm::Device,
        wf: &pwm::Waveform,
    ) -> Result<(i32, Self::WfHw)> {
        let data: &Self = chip.drvdata().ok_or(EINVAL)?;
        let hwpwm = pwm.hwpwm();

        if wf.duty_offset_ns != 0 {
            dev_err!(chip.device(), "PWM-{}: Duty offset not supported\n", hwpwm);
            return Err(ENOTSUPP);
        }

        if wf.period_length_ns == 0 {
            return Ok((
                0,
                Th1520WfHw {
                    enabled: false,
                    ..Default::default()
                },
            ));
        }

        let rate_hz = data.clk.rate().as_hz();

        let period_cycles = wf
            .period_length_ns
            .mul_div(rate_hz as u64, time::NSEC_PER_SEC as u64)
            .ok_or(EINVAL)?;
        if period_cycles > u32::MAX as u64 {
            dev_err!(
                chip.device(),
                "PWM-{}: Calculated period {} cycles is out of range\n",
                hwpwm,
                period_cycles
            );
            return Err(EINVAL);
        }

        let duty_cycles = wf
            .duty_length_ns
            .mul_div(rate_hz as u64, time::NSEC_PER_SEC as u64)
            .ok_or(EINVAL)?;
        if duty_cycles > period_cycles {
            dev_err!(
                chip.device(),
                "PWM-{}: Duty {}ns > period {}ns\n",
                hwpwm,
                wf.duty_length_ns,
                wf.period_length_ns
            );
            return Err(EINVAL);
        }

        let mut ctrl_val = PWM_CONTINUOUS_MODE;
        if pwm.state().polarity() == pwm::Polarity::Normal {
            ctrl_val |= PWM_FPOUT;
        }

        let wfhw = Th1520WfHw {
            period_cycles: period_cycles as u32,
            duty_cycles: duty_cycles as u32,
            ctrl_val,
            enabled: true,
        };

        dev_dbg!(
            chip.device(),
            "wfhw -- Period: {}, Duty: {}, Ctrl: 0x{:x}\n",
            wfhw.period_cycles,
            wfhw.duty_cycles,
            wfhw.ctrl_val
        );
        Ok((0, wfhw))
    }

    fn write_waveform(
        chip: &mut pwm::Chip,
        pwm: &mut pwm::Device,
        wfhw: &Self::WfHw,
        parent_dev: &Device<Bound>,
    ) -> Result {
        let data: &Self = chip.drvdata().ok_or(EINVAL)?;
        let hwpwm = pwm.hwpwm();
        let iomem_guard = data.iomem.access(parent_dev)?;
        let iomap = iomem_guard.deref();
        let was_enabled = pwm.state().enabled();

        if !wfhw.enabled {
            if was_enabled {
                let mut ctrl = iomap.read32(th1520_pwm_ctrl(hwpwm));

                ctrl &= !PWM_CFG_UPDATE;

                iomap.write32(ctrl, th1520_pwm_ctrl(hwpwm));
                iomap.write32(0, th1520_pwm_fp(hwpwm));
                iomap.write32(ctrl | PWM_CFG_UPDATE, th1520_pwm_ctrl(hwpwm));
            }
            return Ok(());
        }

        let ctrl = wfhw.ctrl_val & !PWM_CFG_UPDATE;

        iomap.write32(ctrl, th1520_pwm_ctrl(hwpwm));
        iomap.write32(wfhw.period_cycles, th1520_pwm_per(hwpwm));
        iomap.write32(wfhw.duty_cycles, th1520_pwm_fp(hwpwm));
        iomap.write32(wfhw.ctrl_val | PWM_CFG_UPDATE, th1520_pwm_ctrl(hwpwm));

        if !was_enabled {
            iomap.write32(wfhw.ctrl_val | PWM_START, th1520_pwm_ctrl(hwpwm));
        }

        Ok(())
    }
}

impl Drop for Th1520PwmDriverData {
    fn drop(&mut self) {
        self.clk.disable_unprepare();
    }
}

static TH1520_PWM_OPS: pwm::PwmOpsVTable = pwm::create_pwm_ops::<Th1520PwmDriverData>();

struct Th1520PwmPlatformDriver {
    _registration: pwm::Registration,
}

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

        let chip = pwm::Chip::new(dev, MAX_PWM_NUM, 0)?;

        let drvdata = KBox::new(Th1520PwmDriverData { iomem, clk }, GFP_KERNEL)?;
        chip.set_drvdata(drvdata);

        let registration = pwm::Registration::new(chip, &TH1520_PWM_OPS)?;

        Ok(KBox::new(
            Th1520PwmPlatformDriver {
                _registration: registration,
            },
            GFP_KERNEL,
        )?
        .into())
    }
}

kernel::module_platform_driver! {
    type: Th1520PwmPlatformDriver,
    name: "pwm-th1520",
    author: "Michal Wilczynski <m.wilczynski@samsung.com>",
    description: "T-HEAD TH1520 PWM driver",
    license: "GPL v2",
}
