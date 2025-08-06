// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) VeriSilicon Holdings Co., Ltd.
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#ifndef __VS_TYPE_H__
#define __VS_TYPE_H__

struct vs_dc_info {
	const char *name;
	u8 panel_num;

	/* 0 means no gamma LUT */
	u16 gamma_size;
	u8 gamma_bits;
	u16 pitch_alignment;
};

#endif /* __VS_TYPE_H__ */
