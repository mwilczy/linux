// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) StarFive Technology Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#ifndef __STARFIVE_HDMI_H__
#define __STARFIVE_HDMI_H__

#include <linux/bitfield.h>
#include <linux/bits.h>

/* Helper structs for PLL configuration */
struct pre_pll_config {
	unsigned long pixclock;
	unsigned long tmdsclock;
	u8 prediv;
	u16 fbdiv;
	u8 tmds_div_a;
	u8 tmds_div_b;
	u8 tmds_div_c;
	u8 pclk_div_a;
	u8 pclk_div_b;
	u8 pclk_div_c;
	u8 pclk_div_d;
	u8 vco_div_5_en;
	u32 fracdiv;
};

struct post_pll_config {
	unsigned long tmdsclock;
	u8 prediv;
	u16 fbdiv;
	u8 postdiv;
	u8 post_div_en;
	u8 version;
};

/* StarFive Specific Register Definitions */

#define HDMI_PHY_SYNC				0xce

/* REG: 0x1a0 */
#define STF_INNO_PRE_PLL_CONTROL		0x1a0
#define STF_INNO_PRE_PLL_POWER_DOWN		BIT(0)

/* REG: 0x1a1 */
#define STF_INNO_PRE_PLL_DIV_1			0x1a1

/* REG: 0x1a2 */
#define STF_INNO_PRE_PLL_DIV_2			0x1a2
#define STF_INNO_SPREAD_SPECTRUM_MOD_DOWN	BIT(7)
#define STF_INNO_SPREAD_SPECTRUM_MOD_DISABLE	BIT(6)
#define STF_INNO_PRE_PLL_FRAC_DIV_DISABLE	FIELD_PREP(GENMASK(5, 4), 3)
#define STF_INNO_PRE_PLL_FB_DIV_11_8(x)		FIELD_PREP(GENMASK(3, 0), (x) >> 8)

/* REG: 0x1a3 */
#define STF_INNO_PRE_PLL_DIV_3			0x1a3
#define STF_INNO_PRE_PLL_FB_DIV_7_0(x)		FIELD_PREP(GENMASK(7, 0), x)

/* REG: 0x1a9 */
#define STF_INNO_PRE_PLL_LOCK_STATUS		0x1a9

/* REG: 0x1aa */
#define STF_INNO_POST_PLL_DIV_1			0x1aa
#define STF_INNO_POST_PLL_POST_DIV_ENABLE	GENMASK(3, 2)
#define STF_INNO_POST_PLL_REFCLK_SEL_TMDS	BIT(1)
#define STF_INNO_POST_PLL_POWER_DOWN		BIT(0)

/* REG: 0x1ab */
#define STF_INNO_POST_PLL_DIV_2			0x1ab
#define STF_INNO_POST_PLL_PRE_DIV(x)		FIELD_PREP(GENMASK(5, 0), x)

/* REG: 0x1ac */
#define STF_INNO_POST_PLL_DIV_3			0x1ac

/* REG: 0x1ad */
#define STF_INNO_POST_PLL_DIV_4			0x1ad

/* REG: 0x1af */
#define STF_INNO_POST_PLL_LOCK_STATUS		0x1af

/* REG: 0x1b0 */
#define STF_INNO_BIAS_CONTROL			0x1b0
#define STF_INNO_BIAS_ENABLE			BIT(2)

/* REG: 0x1b2 */
#define STF_INNO_TMDS_CONTROL			0x1b2

/* REG: 0x1b4 */
#define STF_INNO_LDO_CONTROL			0x1b4
#define STF_INNO_LDO_ENABLE			(BIT(2) | BIT(1) | BIT(0))

/* REG: 0x1be */
#define STF_INNO_SERIALIER_CONTROL		0x1be
#define STF_INNO_SERIALIER_ENABLE		(BIT(6) | BIT(5) | BIT(4) | BIT(0))

/* REG: 0x1cc */
#define STF_INNO_RX_CONTROL			0x1cc
#define STF_INNO_RX_ENABLE			(BIT(3) | BIT(2) | BIT(1) | BIT(0))

/* REG: 0x1d1 */
#define STF_INNO_PRE_PLL_FRAC_DIV_H		0x1d1
#define STF_INNO_PRE_PLL_FRAC_DIV_23_16(x)	FIELD_PREP(GENMASK(7, 0), (x) >> 16)
/* REG: 0x1d2 */
#define STF_INNO_PRE_PLL_FRAC_DIV_M		0x1d2
#define STF_INNO_PRE_PLL_FRAC_DIV_15_8(x)	FIELD_PREP(GENMASK(7, 0), (x) >> 8)
/* REG: 0x1d3 */
#define STF_INNO_PRE_PLL_FRAC_DIV_L		0x1d3
#define STF_INNO_PRE_PLL_FRAC_DIV_7_0(x)	FIELD_PREP(GENMASK(7, 0), x)

#endif /* __STARFIVE_HDMI_H__ */