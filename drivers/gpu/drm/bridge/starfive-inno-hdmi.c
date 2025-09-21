// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) StarFive Technology Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/media-bus-format.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

#include <drm/bridge/inno_hdmi.h>
#include <drm/display/drm_hdmi_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_bridge_connector.h>
#include <drm/drm_edid.h>
#include <drm/drm_of.h>

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

enum stf_hdmi_clocks { CLK_SYS = 0, CLK_M, CLK_B, CLK_HDMI_NUM };

struct stf_inno_hdmi {
	struct inno_hdmi *inno;
	struct device *dev;
	struct clk_bulk_data clks[CLK_HDMI_NUM];
	struct reset_control *tx_rst;
	u8 vic;

	/* PLL configuration cache */
	const struct pre_pll_config *pre_cfg;
	const struct post_pll_config *post_cfg;
};

static const struct pre_pll_config pre_pll_cfg_table[] = {
	{ 25175000, 25175000, 1, 100, 2, 3, 3, 12, 3, 3, 4, 0, 0xF55555 },
	{ 25200000, 25200000, 1, 100, 2, 3, 3, 12, 3, 3, 4, 0, 0 },
	{ 27000000, 27000000, 1, 90, 3, 2, 2, 10, 3, 3, 4, 0, 0 },
	{ 27027000, 27027000, 1, 90, 3, 2, 2, 10, 3, 3, 4, 0, 0x170A3D },
	{ 28320000, 28320000, 1, 28, 2, 1, 1, 3, 0, 3, 4, 0, 0x51EB85 },
	{ 30240000, 30240000, 1, 30, 2, 1, 1, 3, 0, 3, 4, 0, 0x3D70A3 },
	{ 31500000, 31500000, 1, 31, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 33750000, 33750000, 1, 33, 2, 1, 1, 3, 0, 3, 4, 0, 0xCFFFFF },
	{ 36000000, 36000000, 1, 36, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 40000000, 40000000, 1, 80, 2, 2, 2, 12, 2, 2, 2, 0, 0 },
	{ 46970000, 46970000, 1, 46, 2, 1, 1, 3, 0, 3, 4, 0, 0xF851EB },
	{ 49500000, 49500000, 1, 49, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 49000000, 49000000, 1, 49, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 50000000, 50000000, 1, 50, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 54000000, 54000000, 1, 54, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 54054000, 54054000, 1, 54, 2, 1, 1, 3, 0, 3, 4, 0, 0x0DD2F1 },
	{ 57284000, 57284000, 1, 57, 2, 1, 1, 3, 0, 3, 4, 0, 0x48B439 },
	{ 58230000, 58230000, 1, 58, 2, 1, 1, 3, 0, 3, 4, 0, 0x3AE147 },
	{ 59341000, 59341000, 1, 59, 2, 1, 1, 3, 0, 3, 4, 0, 0x574BC6 },
	{ 59400000, 59400000, 1, 99, 3, 1, 1, 1, 3, 3, 4, 0, 0 },
	{ 65000000, 65000000, 1, 130, 2, 2, 2, 12, 0, 2, 2, 0, 0 },
	{ 68250000, 68250000, 1, 68, 2, 1, 1, 3, 0, 3, 4, 0, 0x3FFFFF },
	{ 71000000, 71000000, 1, 71, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 74176000, 74176000, 1, 98, 1, 2, 2, 1, 2, 3, 4, 0, 0xE6AE6B },
	{ 74250000, 74250000, 1, 99, 1, 2, 2, 1, 2, 3, 4, 0, 0 },
	{ 75000000, 75000000, 1, 75, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 78750000, 78750000, 1, 78, 2, 1, 1, 3, 0, 3, 4, 0, 0xCFFFFF },
	{ 79500000, 79500000, 1, 79, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 83500000, 83500000, 2, 167, 2, 1, 1, 1, 0, 0, 6, 0, 0 },
	{ 83500000, 104375000, 1, 104, 2, 1, 1, 1, 1, 0, 5, 0, 0x600000 },
	{ 85500000, 85500000, 1, 85, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 85750000, 85750000, 1, 85, 2, 1, 1, 3, 0, 3, 4, 0, 0xCFFFFF },
	{ 85800000, 85800000, 1, 85, 2, 1, 1, 3, 0, 3, 4, 0, 0xCCCCCC },
	{ 88750000, 88750000, 1, 88, 2, 1, 1, 3, 0, 3, 4, 0, 0xCFFFFF },
	{ 89910000, 89910000, 1, 89, 2, 1, 1, 3, 0, 3, 4, 0, 0xE8F5C1 },
	{ 90000000, 90000000, 1, 90, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 101000000, 101000000, 1, 101, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 102250000, 102250000, 1, 102, 2, 1, 1, 3, 0, 3, 4, 0, 0x3FFFFF },
	{ 106500000, 106500000, 1, 106, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 108000000, 108000000, 1, 90, 3, 0, 0, 5, 0, 2, 2, 0, 0 },
	{ 119000000, 119000000, 1, 119, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 131481000, 131481000, 1, 131, 2, 1, 1, 3, 0, 3, 4, 0, 0x7B22D1 },
	{ 135000000, 135000000, 1, 135, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 136750000, 136750000, 1, 136, 2, 1, 1, 3, 0, 3, 4, 0, 0xCFFFFF },
	{ 147180000, 147180000, 1, 147, 2, 1, 1, 3, 0, 3, 4, 0, 0x2E147A },
	{ 148352000, 148352000, 1, 98, 1, 1, 1, 1, 2, 2, 2, 0, 0xE6AE6B },
	{ 148500000, 148500000, 1, 99, 1, 1, 1, 1, 2, 2, 2, 0, 0 },
	{ 154000000, 154000000, 1, 154, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 156000000, 156000000, 1, 156, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 157000000, 157000000, 1, 157, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 162000000, 162000000, 1, 162, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 174250000, 174250000, 1, 145, 3, 0, 0, 5, 0, 2, 2, 0, 0x355555 },
	{ 174500000, 174500000, 1, 174, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 174570000, 174570000, 1, 174, 2, 1, 1, 3, 0, 3, 4, 0, 0x91EB84 },
	{ 175500000, 175500000, 1, 175, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 185590000, 185590000, 1, 185, 2, 1, 1, 3, 0, 3, 4, 0, 0x970A3C },
	{ 187000000, 187000000, 1, 187, 2, 1, 1, 3, 0, 3, 4, 0, 0 },
	{ 241500000, 241500000, 1, 161, 1, 1, 1, 4, 0, 2, 2, 0, 0 },
	{ 241700000, 241700000, 1, 241, 2, 1, 1, 3, 0, 3, 4, 0, 0xB33332 },
	{ 262750000, 262750000, 1, 262, 2, 1, 1, 3, 0, 3, 4, 0, 0xCFFFFF },
	{ 296500000, 296500000, 1, 296, 2, 1, 1, 3, 0, 3, 4, 0, 0x7FFFFF },
	{ 296703000, 296703000, 1, 98, 0, 1, 1, 1, 0, 2, 2, 0, 0xE6AE6B },
	{ 297000000, 297000000, 1, 99, 0, 1, 1, 1, 0, 2, 2, 0, 0 },
	{ 594000000, 594000000, 1, 99, 0, 2, 0, 1, 0, 1, 1, 0, 0 },
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static const struct post_pll_config post_pll_cfg_table[] = {
	{ 25200000, 1, 80, 13, 3, 1 },
	{ 27000000, 1, 40, 11, 3, 1 },
	{ 27027000, 1, 40, 11, 3, 1 },
	{ 33750000, 1, 40, 11, 3, 1 },
	{ 49000000, 1, 20, 1, 3, 3 },
	{ 65000000, 1, 20, 1, 3, 3 },
	{ 74250000, 1, 20, 1, 3, 3 },
	{ 88750000, 1, 20, 1, 3, 3 },
	{ 108000000, 1, 20, 1, 3, 3 },
	{ 148500000, 1, 20, 1, 3, 3 },
	{ 162000000, 1, 20, 1, 3, 3 },
	{ 174250000, 1, 20, 1, 3, 3 },
	{ 187000000, 1, 20, 1, 3, 3 },
	{ 241700000, 1, 20, 1, 3, 3 },
	{ 297000000, 4, 20, 0, 0, 3 },
	{ 594000000, 4, 20, 0, 0, 0 }, //postpll_postdiv_en = 0
	{ /* sentinel */ }
};

static inline u8 hdmi_readb(struct inno_hdmi *hdmi, u16 offset)
{
	return readl_relaxed(hdmi->regs + (offset * 4));
}

static inline void hdmi_writeb(struct inno_hdmi *hdmi, u16 offset, u32 val)
{
	writel_relaxed(val, hdmi->regs + (offset * 4));
}

static void inno_hdmi_config_pll(struct stf_inno_hdmi *stf_hdmi)
{
	struct inno_hdmi *hdmi = stf_hdmi->inno;
	const struct pre_pll_config *pre_cfg = stf_hdmi->pre_cfg;
	const struct post_pll_config *post_cfg = stf_hdmi->post_cfg;
	u8 reg_1ad_value = post_cfg->post_div_en ? post_cfg->postdiv : 0x00;
	u8 reg_1aa_value = post_cfg->post_div_en ? 0x0e : 0x02;
	u8 frac_div2_val;

	/* Power down PLLs before re-configuration */
	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_CONTROL, STF_INNO_PRE_PLL_POWER_DOWN);
	hdmi_writeb(hdmi, STF_INNO_POST_PLL_DIV_1,
		    STF_INNO_POST_PLL_POST_DIV_ENABLE |
		    STF_INNO_POST_PLL_REFCLK_SEL_TMDS |
		    STF_INNO_POST_PLL_POWER_DOWN);

	/* Configure PLL dividers */
	frac_div2_val = STF_INNO_SPREAD_SPECTRUM_MOD_DOWN |
			STF_INNO_SPREAD_SPECTRUM_MOD_DISABLE |
			STF_INNO_PRE_PLL_FB_DIV_11_8(pre_cfg->fbdiv);
	if (!pre_cfg->fracdiv)
		frac_div2_val |= STF_INNO_PRE_PLL_FRAC_DIV_DISABLE;

	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_DIV_1, pre_cfg->prediv);
	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_DIV_2, frac_div2_val);
	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_DIV_3,
		    STF_INNO_PRE_PLL_FB_DIV_7_0(pre_cfg->fbdiv));

	/* Configure fractional divider if used */
	if (pre_cfg->fracdiv) {
		hdmi_writeb(hdmi, STF_INNO_PRE_PLL_FRAC_DIV_L,
			    STF_INNO_PRE_PLL_FRAC_DIV_7_0(pre_cfg->fracdiv));
		hdmi_writeb(hdmi, STF_INNO_PRE_PLL_FRAC_DIV_M,
			    STF_INNO_PRE_PLL_FRAC_DIV_15_8(pre_cfg->fracdiv));
		hdmi_writeb(hdmi, STF_INNO_PRE_PLL_FRAC_DIV_H,
			    STF_INNO_PRE_PLL_FRAC_DIV_23_16(pre_cfg->fracdiv));
	}

	/* Configure post PLL dividers */
	hdmi_writeb(hdmi, STF_INNO_POST_PLL_DIV_2,
		    STF_INNO_POST_PLL_PRE_DIV(post_cfg->prediv));
	hdmi_writeb(hdmi, STF_INNO_POST_PLL_DIV_3, post_cfg->fbdiv & 0xff);
	hdmi_writeb(hdmi, STF_INNO_POST_PLL_DIV_4, reg_1ad_value);

	/* Power up PLLs */
	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_CONTROL, 0x00);
	hdmi_writeb(hdmi, STF_INNO_POST_PLL_DIV_1, reg_1aa_value);
}
static void inno_hdmi_improve_eye_diagram(struct stf_inno_hdmi *stf_hdmi)
{
	struct inno_hdmi *hdmi = stf_hdmi->inno;

	switch (stf_hdmi->vic) {
	case 95:
	case 94:
	case 93:
		hdmi_writeb(hdmi, 0x100, 0x00);
		hdmi_writeb(hdmi, 0x1bb, 0x40);
		hdmi_writeb(hdmi, 0x1bc, 0x40);
		hdmi_writeb(hdmi, 0x1bd, 0x40);
		hdmi_writeb(hdmi, 0x1bf, 0x02);
		hdmi_writeb(hdmi, 0x1c0, 0x22);
		break;
	case 16:
	case 31:
		hdmi_writeb(hdmi, 0x1bf, 0x02);
		hdmi_writeb(hdmi, 0x1c0, 0x22);
		break;
	case 4:
	case 3:
	case 1:
		hdmi_writeb(hdmi, 0x1bf, 0x00);
		hdmi_writeb(hdmi, 0x1c0, 0x00);
		break;
	}
}

static void inno_hdmi_starfive_enable(struct device *dev,
				      struct drm_display_mode *mode)
{
	struct stf_inno_hdmi *stf_hdmi = dev_get_drvdata(dev);
	struct inno_hdmi *hdmi = stf_hdmi->inno;
	unsigned long tmds_rate = mode->clock * 1000;
	unsigned long normalized_rate = (tmds_rate / 1000) * 1000;
	const struct pre_pll_config *pre_cfg = pre_pll_cfg_table;
	const struct post_pll_config *post_cfg = post_pll_cfg_table;
	u32 val;
	int ret;

	for (; pre_cfg->pixclock; pre_cfg++) {
		if (pre_cfg->tmdsclock == normalized_rate &&
		    pre_cfg->pixclock == normalized_rate)
			break;
	}
	if (!pre_cfg->pixclock) {
		dev_err(dev,
			"Could not find pre-PLL config for rate %lu\n",
			tmds_rate);
		return;
	}
	stf_hdmi->pre_cfg = pre_cfg;

	for (; post_cfg->tmdsclock; post_cfg++) {
		if (tmds_rate <= post_cfg->tmdsclock)
			break;
	}
	if (!post_cfg->tmdsclock) {
		dev_err(dev,
			"Could not find post-PLL config for rate %lu\n",
			tmds_rate);
		return;
	}
	stf_hdmi->post_cfg = post_cfg;

	hdmi_writeb(hdmi, STF_INNO_BIAS_CONTROL,
		    hdmi_readb(hdmi, STF_INNO_BIAS_CONTROL) |
			    STF_INNO_BIAS_ENABLE);
	hdmi_writeb(hdmi, STF_INNO_RX_CONTROL, STF_INNO_RX_ENABLE);

	stf_hdmi->vic = drm_match_cea_mode(mode);

	inno_hdmi_config_pll(stf_hdmi);

	ret = readx_poll_timeout(readl_relaxed,
				 hdmi->regs + STF_INNO_PRE_PLL_LOCK_STATUS * 4,
				 val, val & 0x1, 1000, 100000);
	if (ret < 0)
		dev_err(dev, "Timeout waiting for pre-PLL lock\n");

	ret = readx_poll_timeout(readl_relaxed,
				 hdmi->regs + STF_INNO_POST_PLL_LOCK_STATUS * 4,
				 val, val & 0x1, 1000, 100000);
	if (ret < 0)
		dev_err(dev, "Timeout waiting for post-PLL lock\n");

	hdmi_writeb(hdmi, STF_INNO_LDO_CONTROL, STF_INNO_LDO_ENABLE);
	hdmi_writeb(hdmi, STF_INNO_SERIALIER_CONTROL,
		    STF_INNO_SERIALIER_ENABLE);

	inno_hdmi_improve_eye_diagram(stf_hdmi);

	/* Value from vendor driver, includes undocumented 0x80 bit. */
	hdmi_writeb(hdmi, STF_INNO_TMDS_CONTROL, 0x8f);
}

static int starfive_inno_hdmi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct stf_inno_hdmi *stf_hdmi;
	const struct inno_hdmi_plat_data *plat_data;
	int ret;

	stf_hdmi = devm_kzalloc(dev, sizeof(*stf_hdmi), GFP_KERNEL);
	if (!stf_hdmi)
		return -ENOMEM;

	stf_hdmi->dev = dev;

	/* Get SoC-specific resources. The generic driver doesn't know about these. */
	stf_hdmi->tx_rst = devm_reset_control_get_exclusive(dev, "hdmi_tx");
	if (IS_ERR(stf_hdmi->tx_rst))
		return dev_err_probe(dev, PTR_ERR(stf_hdmi->tx_rst), "failed to get tx reset\n");

	/* Populate the clock names */
        stf_hdmi->clks[CLK_SYS].id = "sysclk";
        stf_hdmi->clks[CLK_M].id = "mclk";
        stf_hdmi->clks[CLK_B].id = "bclk";

	ret = devm_clk_bulk_get(dev, CLK_HDMI_NUM, stf_hdmi->clks);
	if (ret)
		return dev_err_probe(dev, ret, "Unable to get clocks\n");

	/* Enable resources so the generic driver can access the hardware */
	ret = clk_bulk_prepare_enable(CLK_HDMI_NUM, stf_hdmi->clks);
	if (ret)
		return ret;

	ret = reset_control_deassert(stf_hdmi->tx_rst);
	if (ret) {
		clk_bulk_disable_unprepare(CLK_HDMI_NUM, stf_hdmi->clks);
		return ret;
	}

	plat_data = of_device_get_match_data(dev);

	/* Store our private data so the .enable hook can find it */
	platform_set_drvdata(pdev, stf_hdmi);

	/* Hand off to the generic library to create and register the bridge */
	stf_hdmi->inno = inno_hdmi_probe(pdev, plat_data);
	if (IS_ERR(stf_hdmi->inno)) {
		reset_control_assert(stf_hdmi->tx_rst);
		clk_bulk_disable_unprepare(CLK_HDMI_NUM, stf_hdmi->clks);
		platform_set_drvdata(pdev, NULL);
		return PTR_ERR(stf_hdmi->inno);
	}

	return 0;
}

static void starfive_inno_hdmi_remove(struct platform_device *pdev)
{
	struct stf_inno_hdmi *stf_hdmi = platform_get_drvdata(pdev);

	/* Call the generic remove function to unregister the bridge */
	//inno_hdmi_remove(stf_hdmi->inno);

	/* Disable our SoC-specific resources */
	reset_control_assert(stf_hdmi->tx_rst);
	clk_bulk_disable_unprepare(CLK_HDMI_NUM, stf_hdmi->clks);
}

/*
 * This table tells the generic bridge driver's mode_valid hook what clock
 * rates are acceptable. We allow everything up to 297MHz (for 4K@30).
 * The actual PHY tuning values are unused as our enable hook handles it.
 */
static struct inno_hdmi_phy_config stf_hdmi_phy_configs[] = {
	{ 297000000, 0x00, 0x00 },
	{ ~0UL, 0x00, 0x00 }, /* Sentinel */
};

static const struct inno_hdmi_plat_ops stf_inno_hdmi_plat_ops = {
	.enable = inno_hdmi_starfive_enable,
};

static const struct inno_hdmi_plat_data stf_inno_hdmi_plat_data = {
	.ops = &stf_inno_hdmi_plat_ops,
	.phy_configs = stf_hdmi_phy_configs,
	.default_phy_config = &stf_hdmi_phy_configs[0],
};

static const struct of_device_id starfive_hdmi_dt_ids[] = {
	{ .compatible = "starfive,jh7110-inno-hdmi",
	  .data = &stf_inno_hdmi_plat_data },
	{}
};
MODULE_DEVICE_TABLE(of, starfive_hdmi_dt_ids);

struct platform_driver starfive_inno_hdmi_driver = {
	.probe = starfive_inno_hdmi_probe,
	.remove = starfive_inno_hdmi_remove,
	.driver = {
		.name = "starfive-inno-hdmi",
		.of_match_table = starfive_hdmi_dt_ids,
	},
};
module_platform_driver(starfive_inno_hdmi_driver);

MODULE_AUTHOR("Michal Wilczynski <m.wilczynski@samsung.com>");
MODULE_DESCRIPTION("StarFive INNO-HDMI Driver");
MODULE_LICENSE("GPL");
