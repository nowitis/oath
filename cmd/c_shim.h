// Copyright (C) 2023 - Perceval Faramaz
// SPDX-License-Identifier: GPL-2.0-only

#ifndef C_SHIM_H
#define C_SHIM_H

#include <stdint.h>
#include <string.h>

#include "definitions.h"

#undef DEFINITIONS_H
#undef PADDED
#undef __packed
#undef SUFFIXED_NAME
#define PADDED
#include "definitions.h"

void build_put_command(
	const void* key, uint8_t key_len, 
	uint64_t counter_or_timestep, uint8_t is_totp, uint8_t needs_touch, uint8_t digits,
	const void* name, uint8_t name_len,
	void* packed_buf);

void build_calculate_command(
	const void* secure_record, size_t secure_record_len, 
	uint64_t time,
	void* packed_buf);

int decrypted_toc_header_packed_size();

int toc_record_descriptor_packed_size();

int oath_calculate_packed_size();

int oath_record_packed_size();

int oath_record_put_packed_size();

int secure_oath_record_packed_size();

int max_name_len();

#endif