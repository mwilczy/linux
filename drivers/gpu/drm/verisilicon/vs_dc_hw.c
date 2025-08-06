// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) VeriSilicon Holdings Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/bits.h>
#include <linux/io.h>
#include <linux/media-bus-format.h>
#include <drm/drm_blend.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_framebuffer.h>

#include "vs_drv.h"
#include "vs_dc_hw.h"

static inline u32 vs_hi_read(struct dc_hw *hw, u32 reg)
{
	return readl(hw->hi_base + reg);
}

static inline void vs_hi_write(struct dc_hw *hw, u32 reg, u32 value)
{
	writel(value, hw->hi_base + reg);
}

static inline void vs_dc_write(struct dc_hw *hw, u32 reg, u32 value)
{
	writel(value, hw->reg_base + reg - DC_REG_BASE);
}

static inline u32 dc_read(struct dc_hw *hw, u32 reg)
{
	return readl(hw->reg_base + reg - DC_REG_BASE);
}

static inline void vs_dc_write_mask(struct dc_hw *hw, u32 reg, u32 val,
				    u32 mask)
{
	vs_dc_write(hw, reg, (dc_read(hw, reg) & ~mask) | (val & mask));
}

static inline void vs_dc_set_bit(struct dc_hw *hw, u32 reg, u32 mask)
{
	vs_dc_write(hw, reg, dc_read(hw, reg) | mask);
}

static inline void vs_dc_clear_bit(struct dc_hw *hw, u32 reg, u32 mask)
{
	vs_dc_write(hw, reg, dc_read(hw, reg) & ~mask);
}

int vs_dc_hw_init(struct vs_drm_device *priv)
{
	return 0;
}

void vs_dc_hw_enable_interrupt(struct vs_drm_device *priv)
{
	struct dc_hw *hw = &priv->hw;

	vs_hi_write(hw, AQ_INTR_ENBL, 0xFFFFFFFF);
}

void vs_dc_hw_disable_interrupt(struct vs_drm_device *priv)
{
	struct dc_hw *hw = &priv->hw;

	vs_hi_write(hw, AQ_INTR_ENBL, 0);
}

void vs_dc_hw_get_interrupt(struct vs_drm_device *priv, u8 *status)
{
	struct dc_hw *hw = &priv->hw;
	u32 intr_status = vs_hi_read(hw, AQ_INTR_ACKNOWLEDGE);

	if (intr_status & BIT(0))
		*status |= BIT(0); /* panel 0 frame done intr */

	if (intr_status & BIT(1))
		*status |= BIT(1); /* panel 1 frame done intr */
}
