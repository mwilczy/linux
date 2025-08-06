// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) VeriSilicon Holdings Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/clk.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_atomic.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_print.h>
#include <drm/drm_vblank.h>

#include "vs_crtc.h"
#include "vs_drv.h"

static void vs_crtc_atomic_destroy_state(struct drm_crtc *crtc,
					 struct drm_crtc_state *state)
{
	__drm_atomic_helper_crtc_destroy_state(state);
	kfree(to_vs_crtc_state(state));
}

static void vs_crtc_reset(struct drm_crtc *crtc)
{
	struct vs_crtc_state *state;

	if (crtc->state)
		vs_crtc_atomic_destroy_state(crtc, crtc->state);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return;

	__drm_atomic_helper_crtc_reset(crtc, &state->base);
}

static struct drm_crtc_state *
vs_crtc_atomic_duplicate_state(struct drm_crtc *crtc)
{
	struct vs_crtc_state *old_state;
	struct vs_crtc_state *state;

	if (!crtc->state)
		return NULL;

	old_state = to_vs_crtc_state(crtc->state);

	state = kmemdup(old_state, sizeof(*old_state), GFP_KERNEL);
		if (!state)
			return NULL;

	__drm_atomic_helper_crtc_duplicate_state(crtc, &state->base);

	return &state->base;
}

static int vs_crtc_enable_vblank(struct drm_crtc *crtc)
{
	struct vs_drm_device *priv = to_vs_drm_private(crtc->dev);

	vs_dc_hw_enable_interrupt(priv);

	return 0;
}

static void vs_crtc_disable_vblank(struct drm_crtc *crtc)
{
	struct vs_drm_device *priv = to_vs_drm_private(crtc->dev);

	vs_dc_hw_disable_interrupt(priv);
}

static const struct drm_crtc_funcs vs_crtc_funcs = {
	.set_config		= drm_atomic_helper_set_config,
	.page_flip		= drm_atomic_helper_page_flip,
	.reset			= vs_crtc_reset,
	.atomic_duplicate_state = vs_crtc_atomic_duplicate_state,
	.atomic_destroy_state	= vs_crtc_atomic_destroy_state,
	.enable_vblank		= vs_crtc_enable_vblank,
	.disable_vblank		= vs_crtc_disable_vblank,
};

static void vs_crtc_atomic_enable(struct drm_crtc *crtc,
				  struct drm_atomic_state *state)
{
	struct vs_drm_device *priv = to_vs_drm_private(crtc->dev);
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);
	struct drm_display_mode *mode = &crtc->state->adjusted_mode;
	int id = to_vs_display_id(crtc);

	if (crtc_state->encoder_type == DRM_MODE_ENCODER_DSI) {
		vs_dc_hw_set_out(priv, OUT_DPI, id);
		clk_set_rate(priv->clocks.dc_parent, mode->clock * 1000);
		clk_set_parent(priv->clocks.channel1, priv->clocks.dc_parent);
	} else {
		vs_dc_hw_set_out(priv, OUT_DP, id);
		clk_set_parent(priv->clocks.channel0, priv->clocks.hdmi_tx);
	}

	vs_dc_hw_enable(priv, id, mode, crtc_state->encoder_type, crtc_state->output_fmt);

	enable_irq(priv->irq);

	drm_crtc_vblank_on(crtc);
}

static void vs_crtc_atomic_disable(struct drm_crtc *crtc,
				   struct drm_atomic_state *state)
{
	struct vs_drm_device *priv = to_vs_drm_private(crtc->dev);
	int id = to_vs_display_id(crtc);

	drm_crtc_vblank_off(crtc);

	disable_irq(priv->irq);

	vs_dc_hw_disable(priv, id);

	if (crtc->state->event && !crtc->state->active) {
		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		crtc->state->event = NULL;
		spin_unlock_irq(&crtc->dev->event_lock);
	}
}

static void vs_dc_set_gamma(struct vs_drm_device *priv, struct drm_crtc *crtc,
			    struct drm_color_lut *lut, unsigned int size)
{
	u16 i, r, g, b;
	u8 bits, id;

	if (size != priv->hw.info->gamma_size) {
		drm_err(crtc->dev, "gamma size does not match!\n");
		return;
	}

	id = to_vs_display_id(crtc);

	bits = priv->hw.info->gamma_bits;
	for (i = 0; i < size; i++) {
		r = drm_color_lut_extract(lut[i].red, bits);
		g = drm_color_lut_extract(lut[i].green, bits);
		b = drm_color_lut_extract(lut[i].blue, bits);
		vs_dc_hw_update_gamma(priv, id, i, r, g, b);

		if (i >= priv->hw.info->gamma_size)
			return;

		priv->hw.gamma[id].gamma[i][0] = r;
		priv->hw.gamma[id].gamma[i][1] = g;
		priv->hw.gamma[id].gamma[i][2] = b;
	}
}

static void vs_crtc_atomic_begin(struct drm_crtc *crtc,
				 struct drm_atomic_state *state)
{
	struct drm_crtc_state *new_state = drm_atomic_get_new_crtc_state(state,
									  crtc);

	struct drm_property_blob *blob = new_state->gamma_lut;
	struct drm_color_lut *lut;
	struct vs_drm_device *priv = to_vs_drm_private(crtc->dev);
	u8 id;

	vs_dc_hw_enable_shadow_register(priv, false);

	id = to_vs_display_id(crtc);
	if (new_state->color_mgmt_changed) {
		if (blob && blob->length) {
			lut = blob->data;
			vs_dc_set_gamma(priv, crtc, lut,
					blob->length / sizeof(*lut));
			vs_dc_hw_enable_gamma(priv, id, true);
		} else {
			vs_dc_hw_enable_gamma(priv, id, false);
		}
	}
}

static void vs_crtc_atomic_flush(struct drm_crtc *crtc,
				 struct drm_atomic_state *state)
{
	struct drm_pending_vblank_event *event = crtc->state->event;
	struct vs_drm_device *priv = to_vs_drm_private(crtc->dev);

	if (event) {
		WARN_ON(drm_crtc_vblank_get(crtc) != 0);

		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_arm_vblank_event(crtc, event);
		crtc->state->event = NULL;
		spin_unlock_irq(&crtc->dev->event_lock);
	}

	vs_dc_hw_enable_shadow_register(priv, true);
}

static const struct drm_crtc_helper_funcs vs_crtc_helper_funcs = {
	.atomic_check = drm_crtc_helper_atomic_check,
	.atomic_enable	= vs_crtc_atomic_enable,
	.atomic_disable = vs_crtc_atomic_disable,
	.atomic_begin	= vs_crtc_atomic_begin,
	.atomic_flush	= vs_crtc_atomic_flush,
};

struct vs_crtc *vs_crtc_create(struct drm_device *drm_dev,
			       const struct vs_dc_info *info)
{
	struct vs_crtc *crtc;
	int ret;

	if (!info)
		return NULL;

	crtc = drmm_crtc_alloc_with_planes(drm_dev, struct vs_crtc, base, NULL,
					   NULL, &vs_crtc_funcs,
					   info->name ? info->name : NULL);

	drm_crtc_helper_add(&crtc->base, &vs_crtc_helper_funcs);

	if (info->gamma_size) {
		ret = drm_mode_crtc_set_gamma_size(&crtc->base,
						   info->gamma_size);
		if (ret)
			return NULL;

		drm_crtc_enable_color_mgmt(&crtc->base, 0, false,
					   info->gamma_size);
	}

	return crtc;
}
