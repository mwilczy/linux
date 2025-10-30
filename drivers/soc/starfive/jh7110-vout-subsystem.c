// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/clk.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

static int jh7110_vout_subsystem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct clk *bus_clk;
	struct reset_control *bus_rst;
	int ret;

	bus_clk = devm_clk_get(dev, NULL);
	if (IS_ERR(bus_clk))
		return dev_err_probe(dev, PTR_ERR(bus_clk), "Failed to get bus clock\n");

	bus_rst = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(bus_rst))
		return dev_err_probe(dev, PTR_ERR(bus_rst), "Failed to get bus reset\n");

	pm_runtime_enable(dev);
	ret = pm_runtime_resume_and_get(dev);
	if (ret < 0) {
		dev_err(dev, "Failed to enable power domain: %d\n", ret);
		pm_runtime_disable(dev);
		return ret;
	}

	ret = clk_prepare_enable(bus_clk);
	if (ret) {
		dev_err(dev, "Failed to enable bus clock: %d\n", ret);
		goto err_pm_put;
	}

	ret = reset_control_deassert(bus_rst);
	if (ret) {
		dev_err(dev, "Failed to deassert bus reset: %d\n", ret);
		goto err_clk_disable;
	}

	dev_info(dev, "VOUT subsystem bus interface is powered on\n");

	ret = of_platform_populate(dev->of_node, NULL, NULL, dev);
	if (ret) {
		dev_err(dev, "Failed to populate child devices: %d\n", ret);
		goto err_reset_assert;
	}

	return 0;

err_reset_assert:
	reset_control_assert(bus_rst);
err_clk_disable:
	clk_disable_unprepare(bus_clk);
err_pm_put:
	pm_runtime_put_sync(dev);
	pm_runtime_disable(dev);
	return ret;
}

static void jh7110_vout_subsystem_remove(struct platform_device *pdev)
{
	of_platform_depopulate(&pdev->dev);

	pm_runtime_put_sync(&pdev->dev);
	pm_runtime_disable(&pdev->dev);
}

static const struct of_device_id vout_subsystem_of_match[] = {
	{ .compatible = "starfive,jh7110-vout-subsystem", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, vout_subsystem_of_match);

static struct platform_driver jh7110_vout_subsystem_driver = {
	.probe = jh7110_vout_subsystem_probe,
	.remove = jh7110_vout_subsystem_remove,
	.driver = {
		.name = "jh7110-vout-subsystem",
		.of_match_table = vout_subsystem_of_match,
	},
};
module_platform_driver(jh7110_vout_subsystem_driver);

MODULE_AUTHOR("Michal Wilczynski <m.wilczynski@samsung.com>");
MODULE_DESCRIPTION("StarFive JH7110 VOUT Subsystem Manager");
MODULE_LICENSE("GPL v2");