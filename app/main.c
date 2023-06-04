// Copyright (C) 2023 - Perceval Faramaz
// SPDX-License-Identifier: GPL-2.0-only

#include "app_proto.h"
#include "definitions.h"
#include <tk1_mem.h>
#include <types.h>
#include <monocypher/monocypher.h>
#include "helpers.h"
#include "assert.h"
#include "system.h"
#include "oath/oath.h"

// clang-format off
static volatile uint32_t *cdi =   (volatile uint32_t *)TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *trng_status  = (volatile uint32_t *)TK1_MMIO_TRNG_STATUS;
static volatile uint32_t *trng_entropy = (volatile uint32_t *)TK1_MMIO_TRNG_ENTROPY;

#define PAYLOAD_MAXLEN (CMDLEN_MAXBYTES - 1)

// clang-format on

const uint8_t app_name0[4] = "tk1 ";
const uint8_t app_name1[4] = "oath";
const uint32_t app_version = 0x00000001;

void get_random(uint8_t *buf, int bytes)
{
	int left = bytes;
	for (;;) {
		while ((*trng_status & (1 << TK1_MMIO_TRNG_STATUS_READY_BIT)) ==
		       0) {
		}
		uint32_t rnd = *trng_entropy;
		if (left > 4) {
			memcpy(buf, &rnd, 4);
			buf += 4;
			left -= 4;
			continue;
		}
		memcpy(buf, &rnd, left);
		break;
	}
}

int main(void)
{
	uint32_t stack;
	struct frame_header hdr; // Used in both directions
	uint8_t cmd[CMDLEN_MAXBYTES];
	uint8_t rsp[CMDLEN_MAXBYTES];
	uint8_t forced_next_command = APP_CMD_LOAD_TOC;

	int32_t nbytes_transferred = 0;

	uint8_t oath_record_buf_encrypted_b = 0;
	uint8_t oath_record_buf[MAX(oath_record_put_t, secure_oath_record_t)];

	uint8_t toc_buf[sizeof(decrypted_toc_t)];
	memset(toc_buf, 0, sizeof(toc_buf));

	uint8_t in;
	uint32_t local_cdi[8];

	qemu_puts("Hello! &stack is on: ");
	qemu_putinthex((uint32_t)&stack);
	qemu_lf();

	// Copy locally the CDI (only word aligned access to CDI)
	wordcpy(local_cdi, (void *)cdi, 8);

	set_led(LED_BLUE);

	for (;;) {
		in = readbyte();
		qemu_puts("Read byte: ");
		qemu_puthex(in);
		qemu_lf();

		if (parseframe(in, &hdr) == -1) {
			qemu_puts("Couldn't parse header\n");
			continue;
		}

		memset(cmd, 0, CMDLEN_MAXBYTES);
		// Read app command, blocking
		read(cmd, hdr.len);

		if (hdr.endpoint == DST_FW) {
			set_led(LED_RED);
			appreply_nok(hdr);
			qemu_puts("Responded NOK to message meant for fw\n");
			continue;
		}

		// Is it for us?
		if (hdr.endpoint != DST_SW) {
			qemu_puts("Message not meant for app. endpoint was 0x");
			qemu_puthex(hdr.endpoint);
			qemu_lf();
			continue;
		}

		// Reset response buffer
		memset(rsp, 0, CMDLEN_MAXBYTES);

		if ((forced_next_command != 0) && (cmd[0] != forced_next_command) && (cmd[0] != APP_CMD_GET_NAMEVERSION)) {
			set_led(LED_RED|LED_BLUE);
			appreply_nok(hdr);
			qemu_puts("Responded NOK as message was not expected\n");
			continue;
		}

		// Min length is 1 byte so this should always be here
		switch (cmd[0]) {
		case APP_CMD_GET_NAMEVERSION:
			qemu_puts("APP_CMD_GET_NAMEVERSION\n");
			// only zeroes if unexpected cmdlen bytelen
			if (hdr.len == 1) {
				memcpy(rsp, app_name0, 4);
				memcpy(rsp + 4, app_name1, 4);
				memcpy(rsp + 8, &app_version, 4);
			}
			appreply(hdr, APP_RSP_GET_NAMEVERSION, rsp);
			break;

		case APP_CMD_LOAD_TOC: {
			qemu_puts("APP_CMD_LOAD_TOC\n");

			const int skipfirst = nbytes_transferred == 0;
			if (skipfirst) {
				memset(&toc_buf[0], 0, sizeof(toc_buf));
				memcpy(&toc_buf[0], &cmd[1], sizeof(decrypted_toc_header_t));
			}

			const decrypted_toc_header_t* header = (decrypted_toc_header_t*)toc_buf;

			if (header->descriptor_count > TOC_DESCRIPTORS_MAXCOUNT) {
				set_led(LED_RED);
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_LOAD_TOC, rsp);
				break;
			}
			else if (header->descriptor_count == 0) {
				set_led(LED_GREEN);
				rsp[0] = STATUS_OK;
				appreply(hdr, APP_RSP_LOAD_TOC, rsp);
				forced_next_command = 0;
				break;
			}

			const int maxbytes = CMDLEN_MAXBYTES - 1;
			const int totalbytes = header->descriptor_count * sizeof(toc_record_descriptor_t) + sizeof(decrypted_toc_header_t);
			const int nbytes = min(totalbytes - nbytes_transferred, maxbytes);
			memcpy(&toc_buf[nbytes_transferred], &cmd[1], nbytes);

			nbytes_transferred += nbytes;

			if (nbytes_transferred == totalbytes) {
				decrypted_toc_t* toc = (decrypted_toc_t*)toc_buf;
				const uint8_t* protected_header_str = (uint8_t*)&toc->header.protected_header;

				int mismatch = crypto_unlock_aead(
					(uint8_t*)toc->descriptors, (const uint8_t *)local_cdi, 
					header->nonce, header->mac, 
					protected_header_str, sizeof(toc_header_protected_t),
					(uint8_t*)toc->descriptors, header->descriptor_count*sizeof(toc_record_descriptor_t));

				if (mismatch < 0) {
					qemu_puts("Failed decrypting record\n");
					set_led(LED_RED|LED_GREEN);
					rsp[0] = STATUS_BAD;
					appreply(hdr, APP_RSP_LOAD_TOC, rsp);
					break;
				}

				nbytes_transferred = 0;
				forced_next_command = 0;
			}
			else {
				forced_next_command = APP_CMD_LOAD_TOC;
			}

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_RSP_LOAD_TOC, rsp);

			break;
		}

		case APP_CMD_GET_LIST: {
			decrypted_toc_t* toc = (decrypted_toc_t*)toc_buf;

			if (nbytes_transferred == 0) {
				if (toc->header.protected_header.settings & TOC_SETTING_TOUCH_YES) {
					wait_touch_ledflash(LED_GREEN, 35000);
				}
				set_led(LED_GREEN);
				rsp[0] = toc->header.descriptor_count;
			}
			else {
				rsp[0] = STATUS_OK;
			}
			
			const int maxbytes = CMDLEN_MAXBYTES - 1;
			const int totalbytes = toc->header.descriptor_count * sizeof(toc_record_descriptor_t);
			const int nbytes = min(totalbytes - abs(nbytes_transferred), maxbytes);

			assert(abs(nbytes_transferred) + nbytes <= (sizeof(toc_buf) - offsetof(decrypted_toc_t, descriptors)));
			assert(1 + nbytes <= sizeof(rsp));
			memcpy(&rsp[1],
			       &toc->descriptors[abs(nbytes_transferred)], nbytes);

			nbytes_transferred -= nbytes;

			if (abs(nbytes_transferred) == totalbytes) {
				nbytes_transferred = 0;
				forced_next_command = 0;
			}
			else {
				forced_next_command = APP_CMD_GET_LIST;
			}

			appreply(hdr, APP_RSP_GET_LIST, rsp);

			break;
		}

		case APP_CMD_GET_ENCRYPTEDTOC: {
			qemu_puts("APP_CMD_GET_ENCRYPTEDTOC\n");

			decrypted_toc_t* toc = (decrypted_toc_t*)toc_buf;
			const int blob_len = (toc->header.descriptor_count * sizeof(toc_record_descriptor_t));

			// ToC empty
			if (toc->header.descriptor_count == 0) {
				set_led(LED_RED);
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_GET_ENCRYPTEDTOC, rsp);
				break;
			}

			const int isfirst = nbytes_transferred == 0;
			if (isfirst) {
				// may have been mutated - let's get a new nonce
				get_random(toc->header.nonce, XCHACHA20_NONCE_LEN);

				const uint8_t* protected_header_str = (uint8_t*)&toc->header.protected_header;

				// encrypt it
				crypto_lock_aead(
					toc->header.mac, (uint8_t*)toc->descriptors,
					(const uint8_t *)local_cdi, toc->header.nonce,
					protected_header_str, sizeof(toc_header_protected_t),
					(uint8_t*)toc->descriptors, blob_len);
			}

			const int maxbytes = CMDLEN_MAXBYTES - 1;
			const int totalbytes = sizeof(decrypted_toc_header_t) + blob_len;
			const int nbytes = min(totalbytes - abs(nbytes_transferred), maxbytes);

			assert(abs(nbytes_transferred) + nbytes <= sizeof(toc_buf));
			assert(1 + nbytes <= sizeof(rsp));
			memcpy(&rsp[1],
			       &toc_buf[abs(nbytes_transferred)], nbytes);

			nbytes_transferred -= nbytes;

			if (abs(nbytes_transferred) == totalbytes) {
				set_led(LED_BLUE | LED_RED);
				nbytes_transferred = 0;
				forced_next_command = APP_CMD_LOAD_TOC;
			}
			else {
				forced_next_command = APP_CMD_GET_ENCRYPTEDTOC;
			}

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_RSP_GET_ENCRYPTEDTOC, rsp);

			break;
		}

		case APP_CMD_PUT: {
			qemu_puts("APP_CMD_PUT\n");
			set_led(LED_BLUE);
			decrypted_toc_t* toc = (decrypted_toc_t*)toc_buf;
			if ((toc->header.descriptor_count + 1) > TOC_DESCRIPTORS_MAXCOUNT) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_PUT, rsp);
				break;
			}

			const int nbytes = min(
				sizeof(oath_record_put_t) - nbytes_transferred, 
				PAYLOAD_MAXLEN);
			assert(nbytes_transferred + nbytes <= sizeof(oath_record_buf));
			assert(1 + nbytes <= sizeof(cmd));
			memcpy(&oath_record_buf[nbytes_transferred], &cmd[1], nbytes);

			nbytes_transferred += nbytes;

			// done receiving the new record
			if (nbytes_transferred == sizeof(oath_record_put_t)) {
				set_led(LED_GREEN);
				nbytes_transferred = 0;

				oath_record_put_t *new_record = (oath_record_put_t*)oath_record_buf;

				// add it to the ToC
				toc_record_descriptor_t *new_descriptor = &toc->descriptors[toc->header.descriptor_count];
				new_descriptor->name_len = new_record->name_len;
				memcpy(new_descriptor->name, new_record->name, new_record->name_len);
				toc->header.descriptor_count += 1;
				memset(new_record->name, 0, RECORD_NAME_MAXLEN);
				
				// encrypt the record straight away
				// to avoid having to reserve more stack memory & copying things around,
				//  we leverage the fact that oath_record_put_t and secure_oath_record_t
				//  both start with oath_record_t
				secure_oath_record_t *secure_record = (secure_oath_record_t*)oath_record_buf;
				
				oath_record_protected_t *protected_metadata = &secure_record->record.protected;
				const uint8_t* protected_metadata_str = (uint8_t*)protected_metadata;
				
				get_random(secure_record->nonce, XCHACHA20_NONCE_LEN);
				crypto_lock_aead(
					secure_record->mac, secure_record->record.encrypted_blob, 
					(const uint8_t *)local_cdi, secure_record->nonce,
					protected_metadata_str, sizeof(oath_record_protected_t),
					secure_record->record.encrypted_blob, sizeof(oath_record_secret_t));
				oath_record_buf_encrypted_b = 1;
				forced_next_command = APP_CMD_PUT_GETRECORD;
			}
			else {
				forced_next_command = APP_CMD_PUT;
			}

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_RSP_PUT, rsp);

			break;
		}

		case APP_CMD_PUT_GETRECORD: {
			qemu_puts("APP_CMD_PUT_GETRECORD\n");
			
			// no PUT command (fully) executed
			if (oath_record_buf_encrypted_b == 0) {
				set_led(LED_RED);
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_PUT_GETRECORD, rsp);
				break;
			}
			
			const int nbytes = sizeof(secure_oath_record_t);
			assert(1 + nbytes <= sizeof(rsp));
			assert(nbytes <= sizeof(oath_record_buf));
			memcpy(&rsp[1], &oath_record_buf[0], nbytes);

			oath_record_buf_encrypted_b = 0;
			forced_next_command = 0;

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_RSP_PUT_GETRECORD, rsp);
			
			break;
		}

		case APP_CMD_CALCULATE: {
			qemu_puts("APP_CMD_CALCULATE\n");

			const int nbytes = sizeof(oath_calculate_t);
			assert(1 + nbytes <= sizeof(cmd));
			assert(nbytes <= sizeof(oath_record_buf));
			memcpy(&oath_record_buf[0], &cmd[1], nbytes);

			oath_calculate_t *oath_calculate = (oath_calculate_t*)oath_record_buf;;
			secure_oath_record_t *secure_record = &oath_calculate->secure_record;

			oath_record_protected_t *protected_metadata = &secure_record->record.protected;
			const uint8_t* protected_metadata_str = (uint8_t*)protected_metadata;

			int mismatch = crypto_unlock_aead(
				secure_record->record.encrypted_blob, (const uint8_t *)local_cdi, 
				secure_record->nonce, secure_record->mac, 
				protected_metadata_str, sizeof(oath_record_protected_t),
				secure_record->record.encrypted_blob, sizeof(oath_record_secret_t));

			if (mismatch < 0) {
				qemu_puts("Failed decrypting record\n");
				set_led(LED_RED);
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_CALCULATE, rsp);
				break;
			}

			if (protected_metadata->properties & OATH_PROP_TOUCH_YES) {
				wait_touch_ledflash(LED_GREEN, 35000);
			}

			oath_record_secret_t *decrypted_record = (oath_record_secret_t*)oath_record_buf;
			oath_record_protected_t *metadata = &secure_record->record.protected;
			uint64_t seq;
			if (metadata->properties & OATH_PROP_TYPE_HOTP) {
				// HOTP
				seq = metadata->counter_or_timestep;
				metadata->counter_or_timestep += 1;
			}
			else {
				// TOTP
				seq = oath_calculate->time / metadata->counter_or_timestep;
			}

			uint32_t response = oath_hotp(decrypted_record->key, decrypted_record->key_len, seq, metadata->digits);
			rsp[1] = response;
			rsp[2] = response >> 8;
			rsp[3] = response >> 16;
			rsp[4] = response >> 24;

			// reencrypt the record with the new counter, if needed
			// note that this is purely "indicative" - the client app is free to request the same 
			//  counter value again, if it has the previous AEAD blob saved. 
			if (metadata->properties & OATH_PROP_TYPE_HOTP) {
				secure_oath_record_t *secure_record = (secure_oath_record_t*)oath_record_buf;
				
				oath_record_protected_t *protected_metadata = &secure_record->record.protected;
				const uint8_t* protected_metadata_str = (uint8_t*)protected_metadata;
				
				get_random(secure_record->nonce, XCHACHA20_NONCE_LEN);
				crypto_lock_aead(
					secure_record->mac, secure_record->record.encrypted_blob, 
					(const uint8_t *)local_cdi, secure_record->nonce,
					protected_metadata_str, sizeof(oath_record_protected_t),
					secure_record->record.encrypted_blob, sizeof(oath_record_secret_t));

				const int nbytes = sizeof(secure_oath_record_t);
				assert(1 + sizeof(response) + nbytes <= sizeof(rsp));
				assert(nbytes <= sizeof(oath_record_buf));
				memcpy(&rsp[1+sizeof(response)], &oath_record_buf[0], nbytes);
			}

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_RSP_CALCULATE, rsp);
			
			break;
		}
		}
	}
}
