/*
 * Copyright (C) 2022, 2023 - Tillitis AB
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "system.h"

static volatile uint32_t *led = (volatile uint32_t *)TK1_MMIO_TK1_LED;
static volatile uint32_t *touch = (volatile uint32_t *)TK1_MMIO_TOUCH_STATUS;

void set_led(uint32_t led_value)
{
	*led = led_value;
}

void forever_redflash()
{
	int led_on = 0;

	for (;;) {
		*led = led_on ? LED_RED : LED_BLACK;
		for (volatile int i = 0; i < 800000; i++) {
		}
		led_on = !led_on;
	}
}

void wait_touch_ledflash(uint32_t ledvalue, uint32_t loopcount)
{
	int led_on = 0;
	// first a write, to ensure no stray touch?
	*touch = 0;
	for (;;) {
		*led = led_on ? ledvalue : 0;
		for (int i = 0; i < loopcount; i++) {
			if (*touch & (1 << TK1_MMIO_TOUCH_STATUS_EVENT_BIT)) {
				goto touched;
			}
		}
		led_on = !led_on;
	}
touched:
	// write, confirming we read the touch event
	*touch = 0;
}
