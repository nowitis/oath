/*
 * Copyright (C) 2023 - Perceval Faramaz
 * Portions Copyright (C) 2022, 2023 - Tillitis AB
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef HELPERS_H
#define HELPERS_H

#include <types.h>

// clang-format off

#define SIZE(Z) (sizeof(Z)/sizeof(char))
#define MAX(X,Y) SIZE(X) > SIZE(Y) ? SIZE(X) : SIZE(Y)

#define offsetof(st, m) \
    ((size_t)((char *)&((st *)0)->m - (char *)0))

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define abs(a) \
   (a < 0 ? -a : a)

// clang-format on

int memcmp(const void *str_l, const void *str_r, uint32_t count);

#endif