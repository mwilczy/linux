// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) VeriSilicon Holdings Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/aperture.h>
#include <linux/clk.h>
#include <linux/component.h>
#include <linux/mfd/syscon.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

#include <drm/clients/drm_client_setup.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_modeset_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_file.h>
#include <drm/drm_gem_dma_helper.h>
#include <drm/drm_module.h>
#include <drm/drm_of.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_vblank.h>

#include "vs_drv.h"

#define DRV_NAME "verisilicon"
#define DRV_DESC "Verisilicon DRM driver"
#define DRV_DATE "20230516"
#define DRV_MAJOR 1
#define DRV_MINOR 0

#define FRAC_16_16(mult, div) (((mult) << 16) / (div))

static const struct vs_dc_info dc8200_info = {
	.name = "DC8200",
	.panel_num = 2,
	.gamma_size = GAMMA_EX_SIZE,
	.gamma_bits = 12,
	.pitch_alignment = 128,
};

#define STARFIVE_SOC_CON8 0x08
#define STARFIVE_MIPI_SEL BIT(3)

static int vs_gem_dumb_create(struct drm_file *file, struct drm_device *dev,
			      struct drm_mode_create_dumb *args)
{
	struct vs_drm_device *priv = to_vs_drm_private(dev);
	unsigned int pitch = DIV_ROUND_UP(args->width * args->bpp, 8);

	args->pitch = ALIGN(pitch, priv->pitch_alignment);
	return drm_gem_dma_dumb_create_internal(file, dev, args);
}

DEFINE_DRM_GEM_FOPS(vs_drm_fops);

static struct drm_driver vs_drm_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_ATOMIC | DRIVER_GEM,

	DRM_GEM_DMA_DRIVER_OPS_WITH_DUMB_CREATE(vs_gem_dumb_create),

	.fops = &vs_drm_fops,
	.name = DRV_NAME,
	.desc = DRV_DESC,
	.major = DRV_MAJOR,
	.minor = DRV_MINOR,
};

static irqreturn_t vs_dc_isr(int irq, void *data)
{
	return IRQ_HANDLED;
}

static int vs_drm_device_init_res(struct vs_drm_device *priv)
{
	struct vs_clocks *clocks = &priv->clocks;
	struct device *dev = priv->base.dev;
	struct platform_device *pdev = to_platform_device(dev);
	int ret;

	priv->hw.hi_base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->hw.hi_base))
		return PTR_ERR(priv->hw.hi_base);

	priv->hw.reg_base = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(priv->hw.reg_base))
		return PTR_ERR(priv->hw.reg_base);

	priv->hw.info = (struct vs_dc_info *)of_device_get_match_data(dev);

	clocks->noc_bus = devm_clk_get(dev, "noc_bus");
	if (IS_ERR(clocks->noc_bus))
		return dev_err_probe(dev, PTR_ERR(clocks->noc_bus),
				     "Failed to get noc_bus clock\n");

	clocks->dc_core = devm_clk_get(dev, "dc_core");
	if (IS_ERR(clocks->dc_core))
		return dev_err_probe(dev, PTR_ERR(clocks->dc_core),
				     "Failed to get dc_core clock\n");

	clocks->axi_core = devm_clk_get(dev, "axi_core");
	if (IS_ERR(clocks->axi_core))
		return dev_err_probe(dev, PTR_ERR(clocks->axi_core),
				     "Failed to get axi_core clock\n");

	clocks->ahb = devm_clk_get(dev, "ahb");
	if (IS_ERR(clocks->ahb))
		return dev_err_probe(dev, PTR_ERR(clocks->ahb),
				     "Failed to get ahb clock\n");

	clocks->channel0 = devm_clk_get(dev, "channel0");
	if (IS_ERR(clocks->channel0))
		return dev_err_probe(dev, PTR_ERR(clocks->channel0),
				     "Failed to get channel0 clock\n");

	clocks->channel1 = devm_clk_get(dev, "channel1");
	if (IS_ERR(clocks->channel1))
		return dev_err_probe(dev, PTR_ERR(clocks->channel1),
				     "Failed to get channel1 clock\n");

	clocks->hdmi_tx = devm_clk_get(dev, "hdmi_tx");
	if (IS_ERR(clocks->hdmi_tx))
		return dev_err_probe(dev, PTR_ERR(clocks->hdmi_tx),
				     "Failed to get hdmi_tx clock\n");

	clocks->dc_parent = devm_clk_get(dev, "dc_parent");
	if (IS_ERR(clocks->dc_parent))
		return dev_err_probe(dev, PTR_ERR(clocks->dc_parent),
				     "Failed to get dc_parent clock\n");

	priv->resets = devm_reset_control_array_get_shared(dev);
	if (IS_ERR(priv->resets))
		return PTR_ERR(priv->resets);

	priv->irq = platform_get_irq(pdev, 0);

	/* do not autoenable, will be enabled later */
	ret = devm_request_irq(dev, priv->irq, vs_dc_isr, IRQF_NO_AUTOEN,
			       dev_name(dev), priv);
	if (ret < 0) {
		dev_err(dev, "Failed to install irq:%u.\n", priv->irq);
		return ret;
	}

	return ret;
}

static int vs_load(struct vs_drm_device *priv)
{
	int ret;

	ret = clk_prepare_enable(priv->clocks.noc_bus);
	if (ret)
		return ret;
	ret = clk_prepare_enable(priv->clocks.dc_core);
	if (ret)
		goto err_disable_noc_bus;
	ret = clk_prepare_enable(priv->clocks.axi_core);
	if (ret)
		goto err_disable_dc_core;
	ret = clk_prepare_enable(priv->clocks.ahb);
	if (ret)
		goto err_disable_axi_core;
	ret = clk_prepare_enable(priv->clocks.channel0);
	if (ret)
		goto err_disable_ahb;
	ret = clk_prepare_enable(priv->clocks.channel1);
	if (ret)
		goto err_disable_channel0;
	ret = clk_prepare_enable(priv->clocks.hdmi_tx);
	if (ret)
		goto err_disable_channel1;
	ret = clk_prepare_enable(priv->clocks.dc_parent);
	if (ret)
		goto err_disable_hdmi_tx;

	reset_control_deassert(priv->resets);

	ret = vs_dc_hw_init(priv);
	if (ret) {
		DRM_ERROR("failed to init DC HW\n");
		goto err_disable_all;
	}

	return 0;

err_disable_all:
	clk_disable_unprepare(priv->clocks.dc_parent);
err_disable_hdmi_tx:
	clk_disable_unprepare(priv->clocks.hdmi_tx);
err_disable_channel1:
	clk_disable_unprepare(priv->clocks.channel1);
err_disable_channel0:
	clk_disable_unprepare(priv->clocks.channel0);
err_disable_ahb:
	clk_disable_unprepare(priv->clocks.ahb);
err_disable_axi_core:
	clk_disable_unprepare(priv->clocks.axi_core);
err_disable_dc_core:
	clk_disable_unprepare(priv->clocks.dc_core);
err_disable_noc_bus:
	clk_disable_unprepare(priv->clocks.noc_bus);
	return ret;
}

static int vs_drm_bind(struct device *dev)
{
	struct vs_drm_device *priv;
	int ret;
	struct drm_device *drm_dev;

	printk("MICHAL vs_drm_bind 1\n");

	priv = devm_drm_dev_alloc(dev, &vs_drm_driver, struct vs_drm_device,
				  base);
	if (IS_ERR(priv))
		return PTR_ERR(priv);

	printk("MICHAL vs_drm_bind 2\n");

	priv->pitch_alignment = 64;
	drm_dev = &priv->base;
	dev_set_drvdata(dev, drm_dev);

	ret = dma_set_coherent_mask(drm_dev->dev, DMA_BIT_MASK(40));
	if (ret)
		return ret;

	printk("MICHAL vs_drm_bind 3\n");

	ret = vs_drm_device_init_res(priv);
	if (ret)
		return ret;

	printk("MICHAL vs_drm_bind 4\n");

	/* Remove existing drivers that may own the framebuffer memory. */
	ret = aperture_remove_all_conflicting_devices(vs_drm_driver.name);
	if (ret)
		return ret;

	printk("MICHAL vs_drm_bind 5\n");

	printk("MICHAL vs_drm_bind 6\n");

	ret = vs_load(priv);
	if (ret)
		return ret;

	printk("MICHAL vs_drm_bind 7\n");

	/* Now try and bind all our sub-components */
	ret = component_bind_all(dev, drm_dev);
	if (ret) {
		ret = -EPROBE_DEFER;
		goto unload;
	}
	printk("MICHAL vs_drm_bind 8\n");

	printk("MICHAL vs_drm_bind 9\n");

	ret = drm_vblank_init(drm_dev, drm_dev->mode_config.num_crtc);
	if (ret)
		goto err_unbind_all;

	printk("MICHAL vs_drm_bind 10\n");

	drm_mode_config_reset(drm_dev);

	printk("MICHAL vs_drm_bind 11\n");

	drmm_kms_helper_poll_init(drm_dev);

	printk("MICHAL vs_drm_bind 12\n");

	ret = drm_dev_register(drm_dev, 0);
	if (ret)
		goto err_unbind_all;

	printk("MICHAL vs_drm_bind 13\n");

	drm_client_setup(drm_dev, NULL);
	printk("MICHAL vs_drm_bind 14\n");

	return 0;

err_unbind_all:
	component_unbind_all(drm_dev->dev, drm_dev);
unload:
	reset_control_assert(priv->resets);

	clk_disable_unprepare(priv->clocks.dc_parent);
	clk_disable_unprepare(priv->clocks.hdmi_tx);
	clk_disable_unprepare(priv->clocks.channel1);
	clk_disable_unprepare(priv->clocks.channel0);
	clk_disable_unprepare(priv->clocks.ahb);
	clk_disable_unprepare(priv->clocks.axi_core);
	clk_disable_unprepare(priv->clocks.dc_core);
	clk_disable_unprepare(priv->clocks.noc_bus);

	return ret;
}

static void vs_drm_unbind(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);
	struct vs_drm_device *priv = to_vs_drm_private(drm_dev);

	reset_control_assert(priv->resets);

	clk_disable_unprepare(priv->clocks.dc_parent);
	clk_disable_unprepare(priv->clocks.hdmi_tx);
	clk_disable_unprepare(priv->clocks.channel1);
	clk_disable_unprepare(priv->clocks.channel0);
	clk_disable_unprepare(priv->clocks.ahb);
	clk_disable_unprepare(priv->clocks.axi_core);
	clk_disable_unprepare(priv->clocks.dc_core);
	clk_disable_unprepare(priv->clocks.noc_bus);

	drm_dev_unregister(drm_dev);
	drm_atomic_helper_shutdown(drm_dev);
	component_unbind_all(drm_dev->dev, drm_dev);
}

static const struct component_master_ops vs_drm_ops = {
	.bind = vs_drm_bind,
	.unbind = vs_drm_unbind,
};

static struct platform_driver *drm_sub_drivers[] = {
#ifdef CONFIG_DRM_INNO_STARFIVE_HDMI
	&starfive_inno_hdmi_driver,
#endif
};

static struct component_match *vs_add_external_components(struct device *dev)
{
	struct component_match *match = NULL;
	struct device_node *node;

#ifdef CONFIG_DRM_INNO_STARFIVE_HDMI
	node = of_graph_get_remote_node(dev->of_node, 0, 0);
	drm_of_component_match_add(dev, &match, component_compare_of, node);
	of_node_put(node);
#endif

	return match ? match : ERR_PTR(-ENODEV);
}

static int vs_drm_platform_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct component_match *match;

	/*
	 * All the planes and CRTC would be created in this platform device,
	 * so external components are encoder + connector.
	 */
	match = vs_add_external_components(dev);
	if (IS_ERR(match))
		return PTR_ERR(match);

	return component_master_add_with_match(dev, &vs_drm_ops, match);
}

static void vs_drm_platform_remove(struct platform_device *pdev)
{
	component_master_del(&pdev->dev, &vs_drm_ops);
}

#ifdef CONFIG_PM_SLEEP
static int vs_drm_suspend(struct device *dev)
{
	return drm_mode_config_helper_suspend(dev_get_drvdata(dev));
}

static int vs_drm_resume(struct device *dev)
{
	drm_mode_config_helper_resume(dev_get_drvdata(dev));

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(vs_drm_pm_ops, vs_drm_suspend, vs_drm_resume);

static const struct of_device_id vs_drm_dt_ids[] = {
	{
		.compatible = "starfive,jh7110-dc8200",
		.data = &dc8200_info,
	},
	{},
};

MODULE_DEVICE_TABLE(of, vs_drm_dt_ids);

static struct platform_driver vs_drm_platform_driver = {
	.probe = vs_drm_platform_probe,
	.remove = vs_drm_platform_remove,

	.driver = {
		.name = DRV_NAME,
		.of_match_table = vs_drm_dt_ids,
		.pm = &vs_drm_pm_ops,
	},
};

static int __init vs_drm_init(void)
{
	int ret;

	ret = platform_register_drivers(drm_sub_drivers,
					ARRAY_SIZE(drm_sub_drivers));
	if (ret)
		return ret;

	ret = drm_platform_driver_register(&vs_drm_platform_driver);
	if (ret)
		platform_unregister_drivers(drm_sub_drivers,
					    ARRAY_SIZE(drm_sub_drivers));

	return ret;
}

static void __exit vs_drm_fini(void)
{
	platform_driver_unregister(&vs_drm_platform_driver);
	platform_unregister_drivers(drm_sub_drivers,
				    ARRAY_SIZE(drm_sub_drivers));
}

module_init(vs_drm_init);
module_exit(vs_drm_fini);

MODULE_AUTHOR("Michal Wilczynski <m.wilczynski@samsung.com>");
MODULE_DESCRIPTION("VeriSilicon DRM Driver");
MODULE_LICENSE("GPL");