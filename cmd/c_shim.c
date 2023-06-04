// Copyright (C) 2023 - Perceval Faramaz
// SPDX-License-Identifier: GPL-2.0-only

#include "c_shim.h"
#include <stdlib.h>
#include <string.h>

void build_put_command(
	const void* key, uint8_t key_len, 
	uint64_t counter_or_timestep, uint8_t is_totp, uint8_t needs_touch, uint8_t digits,
	const void* name, uint8_t name_len,
	void* packed_buf)
{
	oath_record_put_t *packed = (oath_record_put_t*)packed_buf;
	memset(packed_buf, 0, sizeof(packed));

	packed->name_len = name_len;
	memcpy(packed->name, name, name_len);

	oath_record_t *record = &packed->record;
	record->protected.properties = 0;
	record->protected.properties |= (is_totp) ? OATH_PROP_TYPE_TOTP : OATH_PROP_TYPE_HOTP;
	record->protected.properties |= (needs_touch) ? OATH_PROP_TOUCH_YES : OATH_PROP_TOUCH_NO;
	record->protected.digits = digits;
	record->protected.counter_or_timestep = counter_or_timestep;

	oath_record_secret_t *secret = (oath_record_secret_t*)&packed->record.encrypted_blob;
	secret->key_len = key_len;
	memcpy(secret->key, key, key_len);
}

void build_calculate_command(
	const void* secure_record, size_t secure_record_len, 
	uint64_t time,
	void* packed_buf)
{
	oath_calculate_t *packed = (oath_calculate_t*)packed_buf;
	memset(packed_buf, 0, sizeof(packed));

	memcpy((void*)(&packed->secure_record), (void*)secure_record, sizeof(secure_oath_record_t));
	packed->time = time;
}

int decrypted_toc_header_packed_size() {
	return sizeof(decrypted_toc_header_t);
}

int toc_record_descriptor_packed_size() {
	return sizeof(toc_record_descriptor_t);
}

int oath_calculate_packed_size() {
	return sizeof(oath_calculate_t);
}

int oath_record_packed_size() {
	return sizeof(oath_record_t);
}

int oath_record_put_packed_size() {
	return sizeof(oath_record_put_t);
}

int secure_oath_record_packed_size() {
	return sizeof(secure_oath_record_t);
}

int max_name_len() {
	return RECORD_NAME_MAXLEN;
}
