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

/*
 * RGB to YUV2020 conversion parameters
 * RGB2YUV[0] - [8] : C0 - C8;
 * RGB2YUV[9] - [11]: D0 - D2;
 */
static s16 RGB2YUV[RGB_TO_YUV_TABLE_SIZE] = { 230, 594,	 52,  -125, -323, 448,
					      448, -412, -36, 64,   512,  512 };


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

static void dc_load_csc_common(struct dc_hw *hw, const u32 *coef_reg,
				 u32 *regval, u32 offset, u16 len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		vs_dc_write(hw, coef_reg[i] + offset, regval[i]);
}

/**
 * vs_dc_load_crtc_rgb_to_yuv_csc - Crtc load RGB to YUV csc into hardware registers
 * @hw: Pointer to the hardware structure
 * @offset: Offset value for the coefficients
 * @table: Pointer to the table containing the coefficients
 *
 * This function loads the RGB to YUV conversion coefficients from the provided table
 * into the hardware registers. The coefficients are used for crtc color space
 * conversion during video processing.
 */
static void vs_dc_load_crtc_rgb_to_yuv_csc(struct dc_hw *hw, u32 offset, s16 *table)
{
	u32 coef_reg[] = {
		DC_DISPLAY_RGBTOYUV_COEF0, DC_DISPLAY_RGBTOYUV_COEF1,
		DC_DISPLAY_RGBTOYUV_COEF2, DC_DISPLAY_RGBTOYUV_COEF3,
		DC_DISPLAY_RGBTOYUV_COEF4, DC_DISPLAY_RGBTOYUV_COEFD0,
		DC_DISPLAY_RGBTOYUV_COEFD1, DC_DISPLAY_RGBTOYUV_COEFD2,
	};

	u32 regval[ARRAY_SIZE(coef_reg)] = {
		table[0] | (table[1] << 16),// Lower 16 of table[0] and upper 16 of table[1]
		table[2] | (table[3] << 16),// Lower 16 of table[2] and upper 16 of table[3]
		table[4] | (table[5] << 16),// Lower 16 of table[4] and upper 16 of table[5]
		table[6] | (table[7] << 16),// Lower 16 of table[6] and upper 16 of table[7]
		table[8],		    // Direct value from table[8]
		table[9],		    // Direct value from table[9]
		table[10],		    // Direct value from table[10]
		table[11],		    // Direct value from table[11]
	};

	// Load the coefficients into the hardware registers
	dc_load_csc_common(hw, coef_reg, regval, offset, ARRAY_SIZE(coef_reg));
}

int vs_dc_hw_init(struct vs_drm_device *priv)
{
	u8 i, panel_num;
	struct dc_hw *hw = &priv->hw;
	u32 offset;

	panel_num = hw->info->panel_num;
	for (i = 0; i < panel_num; i++) {
		offset = i << 2;

		vs_dc_load_crtc_rgb_to_yuv_csc(hw, offset, RGB2YUV);
		vs_dc_write(hw, DC_DISPLAY_PANEL_CONFIG + offset, PANEL_DE_EN |
			 PANEL_DATA_EN | PANEL_CLOCK_EN);

		offset = i ? DC_CURSOR_OFFSET : 0;
		vs_dc_write(hw, DC_CURSOR_BACKGROUND + offset, 0x00FFFFFF);
		vs_dc_write(hw, DC_CURSOR_FOREGROUND + offset, 0x00AAAAAA);
	}

	return 0;
}

void vs_dc_hw_update_gamma(struct vs_drm_device *priv, u8 id, u16 index,
			u16 r, u16 g, u16 b)
{
	struct dc_hw *hw = &priv->hw;

	if (index >= hw->info->gamma_size)
		return;

	hw->gamma[id].gamma[index][0] = r;
	hw->gamma[id].gamma[index][1] = g;
	hw->gamma[id].gamma[index][2] = b;
}

void vs_dc_hw_enable_gamma(struct vs_drm_device *priv, u8 id, bool enable)
{
	struct dc_hw *hw = &priv->hw;

	u32 value;

	if (enable) {
		vs_dc_write(hw, DC_DISPLAY_GAMMA_EX_INDEX + (id << 2), 0x00);
		for (int i = 0; i < GAMMA_EX_SIZE; i++) {
			value = hw->gamma[id].gamma[i][2] |
				(hw->gamma[id].gamma[i][1] << 12);
			vs_dc_write(hw, DC_DISPLAY_GAMMA_EX_DATA + (id << 2), value);
			vs_dc_write(hw, DC_DISPLAY_GAMMA_EX_ONE_DATA + (id << 2),
				 hw->gamma[id].gamma[i][0]);
		}
		vs_dc_set_bit(hw, DC_DISPLAY_PANEL_CONFIG + (id << 2), PANEL_GAMMA_EN);
	} else {
		vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_CONFIG + (id << 2), PANEL_GAMMA_EN);
	}
}

void vs_dc_hw_enable(struct vs_drm_device *priv, int id, struct drm_display_mode *mode,
		  u8 encoder_type, u32 output_fmt)
{
	u32 dp_cfg, dpi_cfg, offset = id << 2;
	struct dc_hw *hw = &priv->hw;
	bool is_yuv = false;

	if (encoder_type != DRM_MODE_ENCODER_DSI) {
		switch (output_fmt) {
		case MEDIA_BUS_FMT_RGB565_1X16:
			dp_cfg = 0;
			break;
		case MEDIA_BUS_FMT_RGB666_1X18:
			dp_cfg = 1;
			break;
		case MEDIA_BUS_FMT_RGB888_1X24:
			dp_cfg = 2;
			break;
		case MEDIA_BUS_FMT_RGB101010_1X30:
			dp_cfg = 3;
			break;
		case MEDIA_BUS_FMT_UYVY8_1X16:
			dp_cfg = 2 << 4;
			is_yuv = true;
			break;
		case MEDIA_BUS_FMT_YUV8_1X24:
			dp_cfg = 4 << 4;
			is_yuv = true;
			break;
		case MEDIA_BUS_FMT_UYVY10_1X20:
			dp_cfg = 8 << 4;
			is_yuv = true;
			break;
		case MEDIA_BUS_FMT_YUV10_1X30:
			dp_cfg = 10 << 4;
			is_yuv = true;
			break;
		case MEDIA_BUS_FMT_UYYVYY8_0_5X24:
			dp_cfg = 12 << 4;
			is_yuv = true;
			break;
		case MEDIA_BUS_FMT_UYYVYY10_0_5X30:
			dp_cfg = 13 << 4;
			is_yuv = true;
			break;
		default:
			dp_cfg = 2;
			break;
		}
		if (is_yuv)
			vs_dc_set_bit(hw, DC_DISPLAY_PANEL_CONFIG + offset, PANEL_RGB2YUV_EN);
		else
			vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_CONFIG + offset, PANEL_RGB2YUV_EN);
		vs_dc_write(hw, DC_DISPLAY_DP_CONFIG + offset, dp_cfg | DP_SELECT);
	}

	if (hw->out[id] == OUT_DPI)
		vs_dc_clear_bit(hw, DC_DISPLAY_DP_CONFIG + offset, DP_SELECT);

	switch (output_fmt) {
	case MEDIA_BUS_FMT_RGB565_1X16:
		dpi_cfg = 0;
		break;
	case MEDIA_BUS_FMT_RGB666_1X18:
		dpi_cfg = 3;
		break;
	case MEDIA_BUS_FMT_RGB666_1X24_CPADHI:
		dpi_cfg = 4;
		break;
	case MEDIA_BUS_FMT_RGB888_1X24:
		dpi_cfg = 5;
		break;
	case MEDIA_BUS_FMT_RGB101010_1X30:
		dpi_cfg = 6;
		break;
	default:
		dpi_cfg = 5;
		break;
	}
	vs_dc_write(hw, DC_DISPLAY_DPI_CONFIG + offset, dpi_cfg);

	if (id == 0)
		vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_START, PANEL0_EN | TWO_PANEL_EN);
	else
		vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_START, PANEL1_EN | TWO_PANEL_EN);

	vs_dc_write(hw, DC_DISPLAY_H + offset,
		 H_ACTIVE_LEN(mode->hdisplay) |
		 H_TOTAL_LEN(mode->htotal));

	vs_dc_write(hw, DC_DISPLAY_H_SYNC + offset,
		 H_SYNC_START_LEN(mode->hsync_start) |
		 H_SYNC_END_LEN(mode->hsync_end) |
		 H_POLARITY_LEN(mode->flags & DRM_MODE_FLAG_PHSYNC ? 0 : 1) |
		 H_PLUS_LEN(1));

	vs_dc_write(hw, DC_DISPLAY_V + offset,
		 V_ACTIVE_LEN(mode->vdisplay) |
		 V_TOTAL_LEN(mode->vtotal));

	vs_dc_write(hw, DC_DISPLAY_V_SYNC + offset,
		 V_SYNC_START_LEN(mode->vsync_start) |
		 V_SYNC_END_LEN(mode->vsync_end) |
		 V_POLARITY_LEN(mode->flags & DRM_MODE_FLAG_PVSYNC ? 0 : 1) |
		 V_PLUS_LEN(1));

	vs_dc_set_bit(hw, DC_DISPLAY_PANEL_CONFIG + offset, PANEL_OUTPUT_EN);
	vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_START, SYNC_EN);
	vs_dc_set_bit(hw, DC_DISPLAY_PANEL_START, BIT(id));
}

void vs_dc_hw_disable(struct vs_drm_device *priv, int id)
{
	struct dc_hw *hw = &priv->hw;
	u32 offset = id << 2;

	if (hw->out[id] == OUT_DPI)
		vs_dc_clear_bit(hw, DC_DISPLAY_DP_CONFIG + offset, DP_SELECT);
	vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_CONFIG + offset, PANEL_OUTPUT_EN);
	vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_START, BIT(id) | TWO_PANEL_EN);
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

void vs_dc_hw_enable_shadow_register(struct vs_drm_device *priv, bool enable)
{
	struct dc_hw *hw = &priv->hw;
	u32 i, offset;
	u8 panel_num = hw->info->panel_num;

	for (i = 0; i < panel_num; i++) {
		offset = i << 2;
		if (enable)
			vs_dc_clear_bit(hw, DC_DISPLAY_PANEL_CONFIG_EX + offset, PANEL_SHADOW_INVALID);
		else
			vs_dc_set_bit(hw, DC_DISPLAY_PANEL_CONFIG_EX + offset, PANEL_SHADOW_INVALID);
	}
}

void vs_dc_hw_set_out(struct vs_drm_device *priv, enum dc_hw_out out, u8 id)
{
	struct dc_hw *hw = &priv->hw;

	if (out < OUT_MAX)
		hw->out[id] = out;
}
