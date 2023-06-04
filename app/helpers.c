// Copyright (C) 2023 - Perceval Faramaz
// SPDX-License-Identifier: GPL-2.0-only

#include "helpers.h"
#include "assert.h"
#include <lib.h>
#include <proto.h>
#include <tk1_mem.h>

int memcmp(const void *str_l, const void *str_r, uint32_t count)
{
	register const unsigned char *sl = (const unsigned char*)str_l;
	register const unsigned char *sr = (const unsigned char*)str_r;

	while (count-- > 0) {
		if (*sl++ != *sr++) {
			return sl[-1] < sr[-1] ? -1 : 1;
		}
	}
	
	return 0;
}