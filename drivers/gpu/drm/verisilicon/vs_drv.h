// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) VeriSilicon Holdings Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#ifndef __VS_DRV_H__
#define __VS_DRV_H__

#include <linux/platform_device.h>
#include <drm/drm_drv.h>

#include "vs_dc_hw.h"

struct clk;
struct reset_control;
struct regmap;

struct vs_clocks {
	struct clk *noc_bus;
	struct clk *dc_core;
	struct clk *axi_core;
	struct clk *ahb;
	struct clk *channel0;
	struct clk *channel1;
	struct clk *hdmi_tx;
	struct clk *dc_parent;
};

struct vs_drm_device {
	struct drm_device base;
	unsigned int pitch_alignment;

	struct vs_clocks clocks;
	struct reset_control *resets;
	int irq;

	/* Display Controller Hardware State */
	struct dc_hw hw;
};

static inline struct vs_drm_device *
to_vs_drm_private(const struct drm_device *dev)
{
	return container_of(dev, struct vs_drm_device, base);
}

#ifdef CONFIG_DRM_INNO_STARFIVE_HDMI
extern struct platform_driver starfive_inno_hdmi_driver;
#endif

#endif /* __VS_DRV_H__ */
