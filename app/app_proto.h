// Copyright (C) 2023 - Perceval Faramaz
// Portions Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#ifndef APP_PROTO_H
#define APP_PROTO_H

#include <lib.h>
#include <proto.h>
#include <tk1_mem.h>
#include <types.h>

// clang-format off
enum appcmd {
	APP_CMD_GET_NAMEVERSION  = 0x01,
	APP_RSP_GET_NAMEVERSION  = 0x02,

	APP_CMD_LOAD_TOC         = 0x03,
	APP_RSP_LOAD_TOC         = 0x04,

	APP_CMD_GET_LIST         = 0x05,
	APP_RSP_GET_LIST         = 0x06,

	APP_CMD_GET_ENCRYPTEDTOC = 0x07,
	APP_RSP_GET_ENCRYPTEDTOC = 0x08,
	
	APP_CMD_PUT              = 0x09,
	APP_RSP_PUT              = 0x0a,

	APP_CMD_PUT_GETRECORD    = 0x0b,
	APP_RSP_PUT_GETRECORD    = 0x0c,

	APP_CMD_CALCULATE        = 0x0d,
	APP_RSP_CALCULATE        = 0x0e,
	/*
	APP_CMD_VALIDATE         = 0x07,
	APP_RSP_VALIDATE         = 0x08,

	APP_CMD_DELETE           = 0x09,
	APP_RSP_DELETE           = 0x0a,

	*/

	APP_RSP_UNKNOWN_CMD      = 0xff,
};
// clang-format on

void appreply_nok(struct frame_header hdr);
void appreply(struct frame_header hdr, enum appcmd rspcode, void *buf);

#endif
