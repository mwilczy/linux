// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Samsung Electronics Co., Ltd.
// Author: Michal Wilczynski <m.wilczynski@samsung.com>

//! Rust T-HEAD TH1520 PWM driver
use kernel::{c_str, clk::Clk, device, io::mem::IoMem, of, platform, prelude::*, pwm, time};

const MAX_PWM_NUM: u32 = 6;

const fn th1520_pwm_chn_base(n: u32) -> u32 {
    n * 0x20
}
const fn th1520_pwm_ctrl(n: u32) -> u32 {
    th1520_pwm_chn_base(n) + 0x00
}
const fn th1520_pwm_per(n: u32) -> u32 {
    th1520_pwm_chn_base(n) + 0x08
}
const fn th1520_pwm_fp(n: u32) -> u32 {
    th1520_pwm_chn_base(n) + 0x0c
}

const PWM_START: u32 = 1 << 0;
const PWM_CFG_UPDATE: u32 = 1 << 2;
const PWM_CONTINUOUS_MODE: u32 = 1 << 5;
const PWM_FPOUT: u32 = 1 << 8;
const PWM_INFACTOUT: u32 = 1 << 9;

struct Th1520PwmChipData {
    clk: Clk,
    iomem: kernel::devres::Devres<IoMem<0>>,
}

impl Th1520PwmChipData {
    fn _config(
        &self,
        hwpwm: u32,
        duty_ns: u64,
        period_ns: u64,
        target_polarity: pwm::Polarity,
    ) -> Result<u32> {
        let regs = self.iomem.try_access().ok_or_else(|| {
            pr_err!("PWM-{}: Failed to access I/O memory in _config\n", hwpwm);
            EBUSY
        })?;

        // Calculate cycle values
        let rate_hz_u64 = self.clk.rate().as_hz() as u64;

        if duty_ns > period_ns {
            pr_err!(
                "PWM-{}: Duty {}ns > period {}ns\n",
                hwpwm,
                duty_ns,
                period_ns
            );
            return Err(EINVAL);
        }
        if period_ns == 0 {
            pr_err!("PWM-{}: Period is zero\n", hwpwm);
            return Err(EINVAL);
        }

        let mut period_cycle = mul_div_u64(period_ns, rate_hz_u64, time::NSEC_PER_SEC as u64);
        if period_cycle > u32::MAX as u64 {
            period_cycle = u32::MAX as u64;
        }
        if period_cycle == 0 {
            pr_err!(
                "PWM-{}: Calculated period_cycle is zero, not allowed by HW\n",
                hwpwm
            );
            return Err(EINVAL);
        }

        let mut duty_cycle = mul_div_u64(duty_ns, rate_hz_u64, time::NSEC_PER_SEC as u64);
        if duty_cycle > u32::MAX as u64 {
            duty_cycle = u32::MAX as u64;
        }

        let mut base_ctrl_val = PWM_INFACTOUT | PWM_CONTINUOUS_MODE;
        if target_polarity == pwm::Polarity::Normal {
            // FPOUT=1 for Normal
            base_ctrl_val |= PWM_FPOUT;
        } else {
            // Inversed, FPOUT=0
            base_ctrl_val &= !PWM_FPOUT;
        }
        regs.try_write32(base_ctrl_val, th1520_pwm_ctrl(hwpwm) as usize)?;
        pr_debug!(
            "PWM-{}: _config: Initial CTRL write (polarity, mode): 0x{:x}\n",
            hwpwm,
            base_ctrl_val
        );

        // Write period and duty registers
        regs.try_write32(period_cycle as u32, th1520_pwm_per(hwpwm) as usize)?;
        regs.try_write32(duty_cycle as u32, th1520_pwm_fp(hwpwm) as usize)?;
        pr_debug!(
            "PWM-{}: _config: Period_cyc={}, Duty_cyc={}\n",
            hwpwm,
            period_cycle,
            duty_cycle
        );

        // Apply period/duty by toggling CFG_UPDATE from 0 to 1.
        // The `base_ctrl_val` (just written to HW) has CFG_UPDATE=0. Now set it.
        let ctrl_val_for_update = base_ctrl_val | PWM_CFG_UPDATE;
        regs.try_write32(ctrl_val_for_update, th1520_pwm_ctrl(hwpwm) as usize)?;
        pr_debug!(
            "PWM-{}: _config: CTRL write with CFG_UPDATE: 0x{:x}\n",
            hwpwm,
            ctrl_val_for_update
        );

        Ok(ctrl_val_for_update)
    }

    fn _enable(&self, hwpwm: u32, ctrl_val_after_config: u32) -> Result {
        let regs = self.iomem.try_access().ok_or_else(|| {
            pr_err!("PWM-{}: Failed to access I/O memory in _enable\n", hwpwm);
            EBUSY
        })?;

        // ctrl_val_after_config already has mode, polarity, and CFG_UPDATE correctly set.
        // Now add the START bit. START bit auto-clears.
        let ctrl_to_start = ctrl_val_after_config | PWM_START;
        regs.try_write32(ctrl_to_start, th1520_pwm_ctrl(hwpwm) as usize)?;
        pr_debug!(
            "PWM-{}: _enable: CTRL write with START: 0x{:x}\n",
            hwpwm,
            ctrl_to_start
        );
        Ok(())
    }

    fn _disable(&self, hwpwm: u32) -> Result<()> {
        let regs = self.iomem.try_access().ok_or_else(|| {
            pr_err!("PWM-{}: Failed to access I/O memory in _disable\n", hwpwm);
            EINVAL
        })?;

        let mut ctrl_val = regs.try_read32(th1520_pwm_ctrl(hwpwm) as usize)?;
        pr_debug!("PWM-{}: _disable: Read CTRL: 0x{:x}\n", hwpwm, ctrl_val);

        // Ensure CFG_UPDATE is 0 before updating duty (Limitation #4)
        if (ctrl_val & PWM_CFG_UPDATE) != 0 {
            ctrl_val &= !PWM_CFG_UPDATE;
            regs.try_write32(ctrl_val, th1520_pwm_ctrl(hwpwm) as usize)?;
            pr_debug!(
                "PWM-{}: _disable: Cleared CFG_UPDATE, wrote CTRL: 0x{:x}\n",
                hwpwm,
                ctrl_val
            );
        }

        // Set duty cycle to 0
        regs.try_write32(0, th1520_pwm_fp(hwpwm) as usize)?;
        pr_debug!("PWM-{}: _disable: Wrote 0 to DUTY (FP) register\n", hwpwm);

        // Apply the 0% duty by toggling CFG_UPDATE from 0 to 1
        // Use the ctrl_val that has CFG_UPDATE cleared (or was already clear)
        ctrl_val |= PWM_CFG_UPDATE;
        regs.try_write32(ctrl_val, th1520_pwm_ctrl(hwpwm) as usize)?;
        pr_debug!(
            "PWM-{}: _disable: Set CFG_UPDATE, wrote CTRL: 0x{:x}\n",
            hwpwm,
            ctrl_val
        );

        Ok(())
    }
}

impl pwm::PwmOps for Th1520PwmChipData {
    // This driver implements get_state
    fn apply(
        pwm_chip_ref: &mut pwm::Chip,
        pwm_dev: &mut pwm::Device,
        target_state: &pwm::State,
    ) -> Result {
        let data: &Th1520PwmChipData = pwm_chip_ref.get_drvdata().ok_or(EINVAL)?;
        let hwpwm = pwm_dev.hwpwm();

        if !target_state.enabled() {
            if pwm_dev.state().enabled() {
                data._disable(hwpwm)?;
            }

            return Ok(());
        }

        // Configure period, duty, and polarity.
        // This function also latches period/duty with CFG_UPDATE.
        // It returns the control value that was written with CFG_UPDATE set.
        let ctrl_val_after_config = data._config(
            hwpwm,
            target_state.duty_cycle(),
            target_state.period(),
            target_state.polarity(),
        )?;

        // Enable by setting START bit if it wasn't enabled before this apply call
        if !pwm_dev.state().enabled() {
            data._enable(hwpwm, ctrl_val_after_config)?;
        }

        Ok(())
    }
}

impl Drop for Th1520PwmChipData {
    fn drop(&mut self) {
        self.clk.disable_unprepare();
    }
}

fn mul_div_u64(a: u64, b: u64, c: u64) -> u64 {
    if c == 0 {
        return 0;
    }
    a.wrapping_mul(b) / c
}

static TH1520_PWM_OPS: pwm::PwmOpsVTable = pwm::create_pwm_ops::<Th1520PwmChipData>();

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
        pdev: &platform::Device<device::Core>,
        _id_info: Option<&Self::IdInfo>,
    ) -> Result<Pin<KBox<Self>>> {
        let resource = pdev.resource(0).ok_or(ENODEV)?;
        let iomem = pdev.ioremap_resource(&resource)?;

        let clk = Clk::get(pdev.as_ref(), None)?;

        clk.prepare_enable()?;
        let driver_data = KBox::new(Th1520PwmChipData { clk, iomem }, GFP_KERNEL)?;
        let pwm_chip = pwm::devm_chip_alloc(pdev.as_ref(), MAX_PWM_NUM, 0)?;

        let result = pwm::devm_chip_add(pdev.as_ref(), pwm_chip, &TH1520_PWM_OPS);
        if result.is_err() {
            pr_err!("Failed to add PWM chip: {:?}\n", result);
            return Err(EIO);
        }

        pwm_chip.set_drvdata(driver_data);
        pr_info!("T-HEAD TH1520 PWM probed correctly\n");

        Ok(KBox::new(Self, GFP_KERNEL)?.into())
    }
}

kernel::module_platform_driver! {
    type: Th1520PwmPlatformDriver,
    name: "pwm_th1520",
    author: "Michal Wilczynski",
    description: "T-HEAD TH1520 PWM driver",
    license: "GPL v2",
}
