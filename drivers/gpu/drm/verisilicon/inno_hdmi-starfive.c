// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) StarFive Technology Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/clk.h>
#include <linux/component.h>
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

#include "inno_hdmi-starfive.h"
#include "vs_crtc.h"

enum stf_hdmi_clocks {
	CLK_SYS = 0,
	CLK_M,
	CLK_B,
	CLK_HDMI_NUM
};

struct stf_inno_hdmi {
	struct inno_hdmi *base;
	struct device *dev;
	struct drm_encoder encoder;
	struct clk_bulk_data clks[CLK_HDMI_NUM];
	struct reset_control *tx_rst;
	u8 vic;

	/* PLL configuration cache */
	const struct pre_pll_config *pre_cfg;
	const struct post_pll_config *post_cfg;
};

/* Struct for cleaner register write sequences */
typedef struct {
	u16 reg;
	u8 value;
} reg_value_t;

static const struct pre_pll_config pre_pll_cfg_table[] = {
	{ 25175000,  25175000, 1,  100, 2, 3, 3, 12, 3, 3, 4, 0, 0xF55555},
	{ 25200000,  25200000, 1,  100, 2, 3, 3, 12, 3, 3, 4, 0, 0},
	{ 27000000,  27000000, 1,  90, 3, 2, 2, 10, 3, 3, 4, 0, 0},
	{ 27027000,  27027000, 1,  90, 3, 2, 2, 10, 3, 3, 4, 0, 0x170A3D},
	{ 28320000,  28320000, 1,  28, 2, 1, 1,  3, 0, 3, 4, 0, 0x51EB85},
	{ 30240000,  30240000, 1,  30, 2, 1, 1,  3, 0, 3, 4, 0, 0x3D70A3},
	{ 31500000,  31500000, 1,  31, 2, 1, 1,  3, 0, 3, 4, 0, 0x7FFFFF},
	{ 33750000,  33750000, 1,  33, 2, 1, 1,  3, 0, 3, 4, 0, 0xCFFFFF},
	{ 36000000,  36000000, 1,  36, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{ 40000000,  40000000, 1,  80, 2, 2, 2, 12, 2, 2, 2, 0, 0},
	{ 46970000,  46970000, 1,  46, 2, 1, 1,  3, 0, 3, 4, 0, 0xF851EB},
	{ 49500000,  49500000, 1,  49, 2, 1, 1,  3, 0, 3, 4, 0, 0x7FFFFF},
	{ 49000000,  49000000, 1,  49, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{ 50000000,  50000000, 1,  50, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{ 54000000,  54000000, 1,  54, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{ 54054000,  54054000, 1,  54, 2, 1, 1,  3, 0, 3, 4, 0, 0x0DD2F1},
	{ 57284000,  57284000, 1,  57, 2, 1, 1,  3, 0, 3, 4, 0, 0x48B439},
	{ 58230000,  58230000, 1,  58, 2, 1, 1,  3, 0, 3, 4, 0, 0x3AE147},
	{ 59341000,  59341000, 1,  59, 2, 1, 1,  3, 0, 3, 4, 0, 0x574BC6},
	{ 59400000,  59400000, 1,  99, 3, 1, 1,  1, 3, 3, 4, 0, 0},
	{ 65000000,  65000000, 1, 130, 2, 2, 2,  12, 0, 2, 2, 0, 0},
	{ 68250000,  68250000, 1, 68,  2, 1, 1,  3,  0, 3, 4, 0, 0x3FFFFF},
	{ 71000000,  71000000, 1,  71, 2, 1, 1,  3, 0, 3,  4, 0, 0},
	{ 74176000,  74176000, 1,  98, 1, 2, 2,  1, 2, 3, 4, 0, 0xE6AE6B},
	{ 74250000,  74250000, 1,  99, 1, 2, 2,  1, 2, 3, 4, 0, 0},
	{ 75000000,  75000000, 1,  75, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{ 78750000,  78750000, 1,  78, 2, 1, 1,  3, 0, 3, 4, 0, 0xCFFFFF},
	{ 79500000,  79500000, 1,  79, 2, 1, 1,  3, 0, 3, 4, 0, 0x7FFFFF},
	{ 83500000,  83500000, 2, 167, 2, 1, 1,  1, 0, 0,  6, 0, 0},
	{ 83500000, 104375000, 1, 104, 2, 1, 1,  1, 1, 0,  5, 0, 0x600000},
	{ 85500000,  85500000, 1,  85, 2, 1, 1,  3, 0, 3,  4, 0, 0x7FFFFF},
	{ 85750000,  85750000, 1,  85, 2, 1, 1,  3, 0, 3,  4, 0, 0xCFFFFF},
	{ 85800000,  85800000, 1,  85, 2, 1, 1,  3, 0, 3,  4, 0, 0xCCCCCC},
	{ 88750000,  88750000, 1,  88, 2, 1, 1,  3, 0, 3,  4, 0, 0xCFFFFF},
	{ 89910000,  89910000, 1,  89, 2, 1, 1,  3, 0, 3, 4, 0, 0xE8F5C1},
	{ 90000000,  90000000, 1,  90, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{101000000, 101000000, 1, 101, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{102250000, 102250000, 1, 102, 2, 1, 1,  3, 0, 3, 4, 0, 0x3FFFFF},
	{106500000, 106500000, 1, 106, 2, 1, 1,  3, 0, 3, 4, 0, 0x7FFFFF},
	{108000000, 108000000, 1,  90, 3, 0, 0,  5, 0, 2,  2, 0, 0},
	{119000000, 119000000, 1, 119, 2, 1, 1,  3, 0, 3,  4, 0, 0},
	{131481000, 131481000, 1,  131, 2, 1, 1,  3, 0, 3,  4, 0, 0x7B22D1},
	{135000000, 135000000, 1,  135, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{136750000, 136750000, 1,  136, 2, 1, 1,  3, 0, 3, 4, 0, 0xCFFFFF},
	{147180000, 147180000, 1,  147, 2, 1, 1,  3, 0, 3, 4, 0, 0x2E147A},
	{148352000, 148352000, 1,  98, 1, 1, 1,  1, 2, 2, 2, 0, 0xE6AE6B},
	{148500000, 148500000, 1,  99, 1, 1, 1,  1, 2, 2, 2, 0, 0},
	{154000000, 154000000, 1, 154, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{156000000, 156000000, 1, 156, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{157000000, 157000000, 1, 157, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{162000000, 162000000, 1, 162, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{174250000, 174250000, 1, 145, 3, 0, 0,  5, 0, 2, 2, 0, 0x355555},
	{174500000, 174500000, 1, 174, 2, 1, 1,  3, 0, 3, 4, 0, 0x7FFFFF},
	{174570000, 174570000, 1, 174, 2, 1, 1,  3, 0, 3, 4, 0, 0x91EB84},
	{175500000, 175500000, 1, 175, 2, 1, 1,  3, 0, 3, 4, 0, 0x7FFFFF},
	{185590000, 185590000, 1, 185, 2, 1, 1,  3, 0, 3, 4, 0, 0x970A3C},
	{187000000, 187000000, 1, 187, 2, 1, 1,  3, 0, 3, 4, 0, 0},
	{241500000, 241500000, 1, 161, 1, 1, 1,  4, 0, 2,  2, 0, 0},
	{241700000, 241700000, 1, 241, 2, 1, 1,  3, 0, 3,  4, 0, 0xB33332},
	{262750000, 262750000, 1, 262, 2, 1, 1,  3, 0, 3,  4, 0, 0xCFFFFF},
	{296500000, 296500000, 1, 296, 2, 1, 1,  3, 0, 3,  4, 0, 0x7FFFFF},
	{296703000, 296703000, 1,  98, 0, 1, 1,  1, 0, 2,  2, 0, 0xE6AE6B},
	{297000000, 297000000, 1,  99, 0, 1, 1,  1, 0, 2,  2, 0, 0},
	{594000000, 594000000, 1,  99, 0, 2, 0,  1, 0, 1,  1, 0, 0},
	{0, 0, 0,  0, 0, 0, 0,  0, 0, 0,  0, 0, 0},
};

static const struct post_pll_config post_pll_cfg_table[] = {
	{25200000,	1, 80, 13, 3, 1},
	{27000000,	1, 40, 11, 3, 1},
	{27027000,	1, 40, 11, 3, 1},
	{33750000,	1, 40, 11, 3, 1},
	//{33750000,	1, 80, 8, 2},
	{49000000,	1, 20, 1, 3, 3},
	{65000000,	1, 20, 1, 3, 3},
	{74250000,	1, 20, 1, 3, 3},
	{88750000,  1, 20, 1, 3, 3},
	{108000000,  1, 20, 1, 3, 3},
	{148500000, 1, 20, 1, 3, 3},
	{162000000, 1, 20, 1, 3, 3},
	{174250000, 1, 20, 1, 3, 3},
	{187000000, 1, 20, 1, 3, 3},
	{241700000, 1, 20, 1, 3, 3},
	{297000000, 4, 20, 0, 0, 3},
	{594000000, 4, 20, 0, 0, 0},//postpll_postdiv_en = 0
	{ /* sentinel */ }
};


/* Local helpers are now possible because struct inno_hdmi is public */
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
	struct inno_hdmi *hdmi = stf_hdmi->base;
	const struct pre_pll_config *pre_cfg = stf_hdmi->pre_cfg;
	const struct post_pll_config *post_cfg = stf_hdmi->post_cfg;
	u8 reg_1ad_value = post_cfg->post_div_en ? post_cfg->postdiv : 0x00;
	u8 reg_1aa_value = post_cfg->post_div_en ? 0x0e : 0x02;
	u8 frac_div2_val;
	int i;

	dev_info(stf_hdmi->dev, "MICHAL: %s: entry\n", __func__);

	const reg_value_t cfg_pll_data[] = {
		{STF_INNO_PRE_PLL_CONTROL, STF_INNO_PRE_PLL_POWER_DOWN},
		{STF_INNO_POST_PLL_DIV_1, STF_INNO_POST_PLL_POST_DIV_ENABLE |
					 STF_INNO_POST_PLL_REFCLK_SEL_TMDS |
					 STF_INNO_POST_PLL_POWER_DOWN},
		{STF_INNO_PRE_PLL_DIV_1, pre_cfg->prediv},
		{STF_INNO_PRE_PLL_DIV_3, STF_INNO_PRE_PLL_FB_DIV_7_0(pre_cfg->fbdiv)},
		{STF_INNO_POST_PLL_DIV_2, STF_INNO_POST_PLL_PRE_DIV(post_cfg->prediv)},
		{STF_INNO_POST_PLL_DIV_3, post_cfg->fbdiv & 0xff},
		{STF_INNO_POST_PLL_DIV_4, reg_1ad_value},
		{STF_INNO_POST_PLL_DIV_1, reg_1aa_value},
	};

	frac_div2_val = STF_INNO_SPREAD_SPECTRUM_MOD_DOWN |
			STF_INNO_SPREAD_SPECTRUM_MOD_DISABLE |
			STF_INNO_PRE_PLL_FB_DIV_11_8(pre_cfg->fbdiv);
	if (!pre_cfg->fracdiv)
		frac_div2_val |= STF_INNO_PRE_PLL_FRAC_DIV_DISABLE;

	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_DIV_2, frac_div2_val);

	for (i = 0; i < ARRAY_SIZE(cfg_pll_data); i++)
		hdmi_writeb(hdmi, cfg_pll_data[i].reg, cfg_pll_data[i].value);

	if (pre_cfg->fracdiv) {
		hdmi_writeb(hdmi, STF_INNO_PRE_PLL_FRAC_DIV_L,
			    STF_INNO_PRE_PLL_FRAC_DIV_7_0(pre_cfg->fracdiv));
		hdmi_writeb(hdmi, STF_INNO_PRE_PLL_FRAC_DIV_M,
			    STF_INNO_PRE_PLL_FRAC_DIV_15_8(pre_cfg->fracdiv));
		hdmi_writeb(hdmi, STF_INNO_PRE_PLL_FRAC_DIV_H,
			    STF_INNO_PRE_PLL_FRAC_DIV_23_16(pre_cfg->fracdiv));
	}
	hdmi_writeb(hdmi, STF_INNO_PRE_PLL_CONTROL, 0x00);
	dev_info(stf_hdmi->dev, "MICHAL: %s: exit\n", __func__);
}

static void inno_hdmi_improve_eye_diagram(struct stf_inno_hdmi *stf_hdmi)
{
	struct inno_hdmi *hdmi = stf_hdmi->base;

	dev_info(stf_hdmi->dev, "MICHAL: %s: entry\n", __func__);
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
	dev_info(stf_hdmi->dev, "MICHAL: %s: exit\n", __func__);
}

static void inno_hdmi_starfive_enable(struct device *dev, struct drm_display_mode *mode)
{
	struct stf_inno_hdmi *stf_hdmi = dev_get_drvdata(dev);
	struct inno_hdmi *hdmi = stf_hdmi->base;
	unsigned long tmds_rate = mode->clock * 1000;
	unsigned long normalized_rate = (tmds_rate / 1000) * 1000;
	const struct pre_pll_config *pre_cfg = pre_pll_cfg_table;
	const struct post_pll_config *post_cfg = post_pll_cfg_table;
	u32 val;
	int ret;

	dev_info(dev, "MICHAL: %s: entry\n", __func__);

	for (; pre_cfg->pixclock; pre_cfg++) {
		if (pre_cfg->tmdsclock == normalized_rate &&
		    pre_cfg->pixclock == normalized_rate)
			break;
	}
	if (!pre_cfg->pixclock) {
		dev_err(dev, "MICHAL: %s: Could not find pre-PLL config for rate %lu\n",
			__func__, tmds_rate);
		return;
	}
	stf_hdmi->pre_cfg = pre_cfg;
	dev_info(dev, "MICHAL: %s: Found pre-PLL config\n", __func__);

	for (; post_cfg->tmdsclock; post_cfg++) {
		if (tmds_rate <= post_cfg->tmdsclock)
			break;
	}
	if (!post_cfg->tmdsclock) {
		dev_err(dev, "MICHAL: %s: Could not find post-PLL config for rate %lu\n",
			__func__, tmds_rate);
		return;
	}
	stf_hdmi->post_cfg = post_cfg;
	dev_info(dev, "MICHAL: %s: Found post-PLL config\n", __func__);

	hdmi_writeb(hdmi, STF_INNO_BIAS_CONTROL,
		    hdmi_readb(hdmi, STF_INNO_BIAS_CONTROL) | STF_INNO_BIAS_ENABLE);
	hdmi_writeb(hdmi, STF_INNO_RX_CONTROL, STF_INNO_RX_ENABLE);

	stf_hdmi->vic = drm_match_cea_mode(mode);

	inno_hdmi_config_pll(stf_hdmi);

	dev_info(dev, "MICHAL: %s: Polling for pre-PLL lock...\n", __func__);
	ret = readx_poll_timeout(readl_relaxed,
				 hdmi->regs + STF_INNO_PRE_PLL_LOCK_STATUS * 4,
				 val, val & 0x1, 1000, 100000);
	if (ret < 0)
		dev_err(dev, "MICHAL: %s: Timeout waiting for pre-PLL lock\n", __func__);
	dev_info(dev, "MICHAL: %s: Pre-PLL lock poll finished\n", __func__);

	dev_info(dev, "MICHAL: %s: Polling for post-PLL lock...\n", __func__);
	ret = readx_poll_timeout(readl_relaxed,
				 hdmi->regs + STF_INNO_POST_PLL_LOCK_STATUS * 4,
				 val, val & 0x1, 1000, 100000);
	if (ret < 0)
		dev_err(dev, "MICHAL: %s: Timeout waiting for post-PLL lock\n", __func__);
	dev_info(dev, "MICHAL: %s: Post-PLL lock poll finished\n", __func__);

	hdmi_writeb(hdmi, STF_INNO_LDO_CONTROL, STF_INNO_LDO_ENABLE);
	hdmi_writeb(hdmi, STF_INNO_SERIALIER_CONTROL, STF_INNO_SERIALIER_ENABLE);

	inno_hdmi_improve_eye_diagram(stf_hdmi);

	/* Value from vendor driver, includes undocumented 0x80 bit. */
	hdmi_writeb(hdmi, STF_INNO_TMDS_CONTROL, 0x8f);
	dev_info(dev, "MICHAL: %s: exit\n", __func__);
}

static int inno_hdmi_starfive_encoder_atomic_check(struct drm_encoder *encoder,
						  struct drm_crtc_state *crtc_state,
						  struct drm_connector_state *conn_state)
{
	struct vs_crtc_state *vs_state = to_vs_crtc_state(crtc_state);

	vs_state->encoder_type = encoder->encoder_type;
	vs_state->output_fmt = MEDIA_BUS_FMT_RGB888_1X24;

	return 0;
}

static const struct drm_encoder_helper_funcs inno_hdmi_starfive_encoder_helper_funcs = {
	.atomic_check = inno_hdmi_starfive_encoder_atomic_check,
};

static int inno_hdmi_starfive_bind(struct device *dev, struct device *master,
				   void *data)
{
	struct drm_device *drm = data;
	struct stf_inno_hdmi *stf_hdmi;
	struct drm_encoder *encoder;
	struct drm_connector *connector;
	const struct inno_hdmi_plat_data *plat_data;
	int ret;

	dev_info(dev, "MICHAL: %s: entry\n", __func__);

	stf_hdmi = devm_kzalloc(dev, sizeof(*stf_hdmi), GFP_KERNEL);
	if (!stf_hdmi)
		return -ENOMEM;

	stf_hdmi->dev = dev;
	dev_set_drvdata(dev, stf_hdmi);

	plat_data = of_device_get_match_data(dev);
	if (!plat_data)
		return -EINVAL;
	dev_info(dev, "MICHAL: %s: Got platform data\n", __func__);

	stf_hdmi->tx_rst = devm_reset_control_get_exclusive(dev, "hdmi_tx");
	if (IS_ERR(stf_hdmi->tx_rst))
		return dev_err_probe(dev, PTR_ERR(stf_hdmi->tx_rst),
				     "failed to get tx reset\n");
	dev_info(dev, "MICHAL: %s: Got reset control\n", __func__);

	ret = devm_clk_bulk_get(dev, CLK_HDMI_NUM, stf_hdmi->clks);
	if (ret)
		return dev_err_probe(dev, ret, "Unable to get clocks\n");
	dev_info(dev, "MICHAL: %s: Got clocks\n", __func__);

	ret = clk_bulk_prepare_enable(CLK_HDMI_NUM, stf_hdmi->clks);
	if (ret)
		return ret;
	dev_info(dev, "MICHAL: %s: Clocks enabled\n", __func__);

	ret = reset_control_deassert(stf_hdmi->tx_rst);
	if (ret)
		goto err_disable_clks;
	dev_info(dev, "MICHAL: %s: Reset deasserted\n", __func__);

	encoder = &stf_hdmi->encoder;
	encoder->possible_crtcs = drm_of_find_possible_crtcs(drm, dev->of_node);
	if (encoder->possible_crtcs == 0) {
		ret = -EPROBE_DEFER;
		goto err_assert_reset;
	}

	ret = drmm_encoder_init(drm, encoder, NULL, DRM_MODE_ENCODER_TMDS, NULL);
	if (ret)
		goto err_assert_reset;

	drm_encoder_helper_add(encoder, &inno_hdmi_starfive_encoder_helper_funcs);

	dev_info(dev, "MICHAL: %s: Calling inno_hdmi_bind...\n", __func__);
	stf_hdmi->base = inno_hdmi_bind(dev, encoder, plat_data);
	if (IS_ERR(stf_hdmi->base)) {
		ret = PTR_ERR(stf_hdmi->base);
		goto err_assert_reset;
	}
	dev_info(dev, "MICHAL: %s: inno_hdmi_bind successful\n", __func__);

	connector = drm_bridge_connector_init(drm, encoder);
	if (IS_ERR(connector)) {
		ret = PTR_ERR(connector);
		dev_err(dev, "failed to init bridge connector: %d\n", ret);
		goto err_assert_reset;
	}

	drm_connector_attach_encoder(connector, encoder);

	dev_info(dev, "MICHAL: %s: exit\n", __func__);
	return 0;

err_assert_reset:
	dev_err(dev, "MICHAL: %s: error path, asserting reset\n", __func__);
	reset_control_assert(stf_hdmi->tx_rst);
err_disable_clks:
	dev_err(dev, "MICHAL: %s: error path, disabling clocks\n", __func__);
	clk_bulk_disable_unprepare(CLK_HDMI_NUM, stf_hdmi->clks);
	return ret;
}

static void inno_hdmi_starfive_unbind(struct device *dev, struct device *master,
				      void *data)
{
	struct stf_inno_hdmi *stf_hdmi = dev_get_drvdata(dev);
	dev_info(dev, "MICHAL: %s: entry\n", __func__);

	reset_control_assert(stf_hdmi->tx_rst);
	clk_bulk_disable_unprepare(CLK_HDMI_NUM, stf_hdmi->clks);
	dev_info(dev, "MICHAL: %s: exit\n", __func__);
}

static const struct component_ops inno_hdmi_starfive_ops = {
	.bind = inno_hdmi_starfive_bind,
	.unbind = inno_hdmi_starfive_unbind,
};

static int inno_hdmi_starfive_probe(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "MICHAL: %s: entry\n", __func__);
	return component_add(&pdev->dev, &inno_hdmi_starfive_ops);
}

static void inno_hdmi_starfive_remove(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "MICHAL: %s: entry\n", __func__);
	component_del(&pdev->dev, &inno_hdmi_starfive_ops);
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
	.probe = inno_hdmi_starfive_probe,
	.remove = inno_hdmi_starfive_remove,
	.driver = {
		.name = "starfive-inno-hdmi",
		.of_match_table = starfive_hdmi_dt_ids,
	},
};
module_platform_driver(starfive_inno_hdmi_driver);

MODULE_AUTHOR("Michal Wilczynski <m.wilczynski@samsung.com>");
MODULE_DESCRIPTION("StarFive INNO-HDMI Driver");
MODULE_LICENSE("GPL");