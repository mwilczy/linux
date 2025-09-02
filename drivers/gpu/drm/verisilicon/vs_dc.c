/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Icenowy Zheng <uwu@icenowy.me>
 */

#include <linux/of.h>
#include <linux/of_graph.h>

#include "vs_crtc.h"
#include "vs_dc.h"
#include "vs_dc_top_regs.h"
#include "vs_drm.h"
#include "vs_hwdb.h"

static const struct regmap_config vs_dc_regmap_cfg = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = sizeof(u32),
	/* VSDC_OVL_CONFIG_EX(1) */
	.max_register = 0x2544,
	.cache_type = REGCACHE_NONE,
};

static const struct of_device_id vs_dc_driver_dt_match[] = {
	{ .compatible = "verisilicon,dc" },
	{},
};
MODULE_DEVICE_TABLE(of, vs_dc_driver_dt_match);

static irqreturn_t vs_dc_irq_handler(int irq, void *private)
{
	struct vs_dc *dc = private;
	u32 irqs;

	printk("MICHAL BEFORE TRYING TO ACKNOWLEDGE INTERRUPT\n");

	regmap_read(dc->regs, VSDC_TOP_IRQ_ACK, &irqs);

	printk("AFTER TRYING TO ACKNOWLEDGE INTERRUPT\n");

	return vs_drm_handle_irq(dc, irqs);
}

static int vs_dc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct vs_dc *dc;
	void __iomem *regs;
	unsigned int i;
	int irq, ret;

	dc = devm_kzalloc(dev, sizeof(*dc), GFP_KERNEL);
	if (!dc)
		return -ENOMEM;
	dev_set_drvdata(dev, dc);

	/* Step 1: Get handles for all clocks */
	dc->noc_bus_clk = devm_clk_get(dev, "noc_bus");
	if (IS_ERR(dc->noc_bus_clk))
		return dev_err_probe(dev, PTR_ERR(dc->noc_bus_clk), "Failed to get noc_bus clock\n");

	dc->core_clk = devm_clk_get(dev, "core");
	if (IS_ERR(dc->core_clk))
		return dev_err_probe(dev, PTR_ERR(dc->core_clk), "Failed to get core clock\n");

	dc->axi_clk = devm_clk_get(dev, "axi");
	if (IS_ERR(dc->axi_clk))
		return dev_err_probe(dev, PTR_ERR(dc->axi_clk), "Failed to get axi clock\n");

	dc->ahb_clk = devm_clk_get(dev, "ahb");
	if (IS_ERR(dc->ahb_clk))
		return dev_err_probe(dev, PTR_ERR(dc->ahb_clk), "Failed to get ahb clock\n");

	dc->dc_parent_clk = devm_clk_get(dev, "dc_parent");
	if (IS_ERR(dc->dc_parent_clk))
		return dev_err_probe(dev, PTR_ERR(dc->dc_parent_clk), "Failed to get dc_parent clock\n");

	dc->outputs = of_graph_get_port_count(dev->of_node);
	for (i = 0; i < dc->outputs; i++) {
		char pixclk_name[5];
		snprintf(pixclk_name, sizeof(pixclk_name), "pix%u", i);
		dc->pix_clk[i] = devm_clk_get(dev, pixclk_name);
		if (IS_ERR(dc->pix_clk[i]))
			return dev_err_probe(dev, PTR_ERR(dc->pix_clk[i]), "Failed to get pixel clk %u\n", i);
	}

	/* Step 2: Get handles for all resets */
	dc->rsts[0].id = "axi";
	dc->rsts[1].id = "ahb";
	dc->rsts[2].id = "core";
	dc->rsts[3].id = "noc_bus";

	/* Step 2: Get all resets by name in one call */
	ret = devm_reset_control_bulk_get_exclusive(dev, VSDC_RESET_COUNT, dc->rsts);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to get bulk resets\n");


	/* Step 3: Enable clocks before de-asserting resets */
	ret = clk_prepare_enable(dc->noc_bus_clk);
	if (ret) return ret;
	ret = clk_prepare_enable(dc->core_clk);
	if (ret) goto err_disable_noc;
	ret = clk_prepare_enable(dc->axi_clk);
	if (ret) goto err_disable_core;
	ret = clk_prepare_enable(dc->ahb_clk);
	if (ret) goto err_disable_axi;
	ret = clk_prepare_enable(dc->dc_parent_clk);
	if (ret) goto err_disable_ahb;


	ret = reset_control_bulk_deassert(VSDC_RESET_COUNT, dc->rsts);
	if (ret) {
		dev_err(dev, "Failed to de-assert bulk resets: %d\n", ret);
		// goto clock cleanup
		return ret;
	}

	/*
	 * Step 5: Map registers and continue probe.
	 * This is now safe.
	 */
	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs)) {
		ret = PTR_ERR(regs);
		goto err_disable_parent;
	}

	dc->regs = devm_regmap_init_mmio(dev, regs, &vs_dc_regmap_cfg);
	if (IS_ERR(dc->regs)) {
		ret = PTR_ERR(dc->regs);
		goto err_disable_parent;
	}

	ret = vs_fill_chip_identity(dc->regs, &dc->identity);
	if (ret)
		goto err_disable_parent;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		ret = irq;
		goto err_disable_parent;
	}

	ret = devm_request_irq(dev, irq, vs_dc_irq_handler, 0, dev_name(dev), dc);
	if (ret)
		goto err_disable_parent;

	ret = vs_drm_initialize(dc, pdev);
	if (ret)
		goto err_disable_parent;

	dev_info(dev, "MICHAL Probe successful!\n");
	return 0;

err_disable_parent:
	clk_disable_unprepare(dc->dc_parent_clk);
err_disable_ahb:
	clk_disable_unprepare(dc->ahb_clk);
err_disable_axi:
	clk_disable_unprepare(dc->axi_clk);
err_disable_core:
	clk_disable_unprepare(dc->core_clk);
err_disable_noc:
	clk_disable_unprepare(dc->noc_bus_clk);
	return ret;
}

static void vs_dc_remove(struct platform_device *pdev)
{
	struct vs_dc *dc = platform_get_drvdata(pdev);

	/* Step 1: Assert resets */
	reset_control_bulk_assert(VSDC_RESET_COUNT, dc->rsts);

	/* Step 2: Disable clocks */
	clk_disable_unprepare(dc->dc_parent_clk);
	clk_disable_unprepare(dc->ahb_clk);
	clk_disable_unprepare(dc->axi_clk);
	clk_disable_unprepare(dc->core_clk);
	clk_disable_unprepare(dc->noc_bus_clk);
}

static void vs_dc_shutdown(struct platform_device *pdev)
{
	struct vs_dc *dc = dev_get_drvdata(&pdev->dev);

	vs_drm_shutdown_handler(dc);
}

struct platform_driver vs_dc_platform_driver = {
	.probe = vs_dc_probe,
	.remove = vs_dc_remove,
	.shutdown = vs_dc_shutdown,
	.driver = {
		.name = "verisilicon-dc",
		.of_match_table = vs_dc_driver_dt_match,
	},
};

module_platform_driver(vs_dc_platform_driver);

MODULE_AUTHOR("Icenowy Zheng <uwu@icenowy.me>");
MODULE_DESCRIPTION("Verisilicon display controller driver");
MODULE_LICENSE("GPL");
