// SPDX-License-Identifier: GPL-2.0
/*
 * MFD Driver for StarFive JH7110 HDMI
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 *
 * This driver binds to the monolithic HDMI block and creates separate
 * logical platform devices for the HDMI Controller (bridge) and the
 * HDMI PHY (clock/phy provider), allowing them to share a single regmap
 * and breaking the probing circular dependency.
 */

#include <linux/clk.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

static const struct regmap_config starfive_hdmi_regmap_config = {
	.reg_bits = 32,
	.val_bits = 8,
	.reg_stride = 4,
	.max_register = 0x4000,
};

static int starfive_hdmi_mfd_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	void __iomem *regs;
	struct regmap *regmap;
	int ret;

	printk("MICHAL starfive_hdmi_mfd_probe 1\n");

	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	regmap = devm_regmap_init_mmio(dev, regs,
				       &starfive_hdmi_regmap_config);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap),
				     "Failed to init shared regmap\n");

	printk("MICHAL starfive_hdmi_mfd_probe 2\n");

	ret = devm_of_platform_populate(dev);
	printk("MICHAL starfive_hdmi_mfd_probe 3\n");
	if (ret)
		dev_err(dev, "Failed to populate child devices: %d\n", ret);

	return ret;
}

static const struct of_device_id starfive_hdmi_mfd_of_match[] = {
	{ .compatible = "starfive,jh7110-hdmi-mfd", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, starfive_hdmi_mfd_of_match);

static struct platform_driver starfive_hdmi_mfd_driver = {
	.probe = starfive_hdmi_mfd_probe,
	.driver = {
		.name = "starfive-hdmi-mfd",
		.of_match_table = starfive_hdmi_mfd_of_match,
	},
};
module_platform_driver(starfive_hdmi_mfd_driver);

MODULE_AUTHOR("Michal Wilczynski <m.wilczynski@samsung.com>");
MODULE_DESCRIPTION("StarFive JH7110 HDMI MFD Driver");
MODULE_LICENSE("GPL v2");