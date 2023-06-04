// Copyright (C) 2023 - Perceval Faramaz
// SPDX-License-Identifier: GPL-2.0-only

#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#ifdef PADDED
#define __packed
#define SUFFIXED_NAME(NAME) NAME##_padded_t

#else
#define __packed __attribute__((packed))
#define SUFFIXED_NAME(NAME) NAME##_t

#endif

#define TOC_DESCRIPTORS_MAXCOUNT 	32
#define TOC_SETTING_TOUCH_NO		(0<<7)
#define TOC_SETTING_TOUCH_YES		(1<<7)

#define RECORD_NAME_MAXLEN 64
#define RECORD_KEY_MAXLEN 66 // 64 + 2 for algo & digits

#define XCHACHA20_NONCE_LEN 24
#define XCHACHA20_MAC_LEN 16


#define OATH_PROP_TYPE_TOTP			(0<<7)
#define OATH_PROP_TYPE_HOTP			(1<<7)

#define OATH_PROP_ALG_SHA			((0<<6)|(0<<5))
#define OATH_PROP_ALG_SHA256		((0<<6)|(1<<5))
#define OATH_PROP_ALG_SHA512		((1<<6)|(0<<5))
#define OATH_PROP_ALG_UNDEFINED		((1<<6)|(1<<5))

#define OATH_PROP_TOUCH_NO			(0<<4)
#define OATH_PROP_TOUCH_YES			(1<<4)

typedef struct {
	uint8_t key_len;
	// Byte 0 is type(higher half)/algorithm(lower half).
	// Byte 1 is number of digits.
	// Remaining is the secret.
	uint8_t key[RECORD_KEY_MAXLEN];
} __packed SUFFIXED_NAME(oath_record_secret);

typedef struct {
	uint64_t counter_or_timestep;
	uint8_t properties;
	uint8_t digits;
} __packed SUFFIXED_NAME(oath_record_protected);

typedef struct {
	uint8_t encrypted_blob[sizeof(SUFFIXED_NAME(oath_record_secret))];
	SUFFIXED_NAME(oath_record_protected) protected;
} __packed SUFFIXED_NAME(oath_record);

typedef struct {
	SUFFIXED_NAME(oath_record) record;
	uint8_t nonce[XCHACHA20_NONCE_LEN];
	uint8_t mac[XCHACHA20_MAC_LEN];
} __packed SUFFIXED_NAME(secure_oath_record);


typedef struct {
	SUFFIXED_NAME(oath_record) record;
	uint8_t name_len;
	uint8_t name[RECORD_NAME_MAXLEN];
} __packed SUFFIXED_NAME(oath_record_put);

typedef struct {
	SUFFIXED_NAME(secure_oath_record) secure_record;
	uint32_t time;
} __packed SUFFIXED_NAME(oath_calculate);


typedef struct {
	uint8_t name_len;
	uint8_t name[RECORD_NAME_MAXLEN];
} __packed SUFFIXED_NAME(toc_record_descriptor);

typedef struct {
	uint8_t settings;
} __packed SUFFIXED_NAME(toc_header_protected);

typedef struct {
	uint8_t descriptor_count;
	uint8_t nonce[XCHACHA20_NONCE_LEN];
	uint8_t mac[XCHACHA20_MAC_LEN];
	SUFFIXED_NAME(toc_header_protected) protected_header;
} __packed SUFFIXED_NAME(decrypted_toc_header);

typedef struct {
	SUFFIXED_NAME(decrypted_toc_header) header;
	SUFFIXED_NAME(toc_record_descriptor) descriptors[TOC_DESCRIPTORS_MAXCOUNT];
} __packed SUFFIXED_NAME(decrypted_toc);

#endif