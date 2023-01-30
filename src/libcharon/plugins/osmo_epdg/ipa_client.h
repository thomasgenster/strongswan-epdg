/*
 * Copyright (C) 2023 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <acouzens@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

// TODO: check license

/**
 * @defgroup osmo_epdg_ipa_client osmo_epdg_ipa_client
 * @{ @ingroup eap_simaka_sql
 */

#ifndef OSMO_EPDG_IPA_CLIENT_H_
#define OSMO_EPDG_IPA_CLIENT_H_

#include <utils/chunk.h>

struct msgb;
typedef struct osmo_epdg_ipa_client_t osmo_epdg_ipa_client_t;
typedef bool (*ipa_cb_t)(void *data, osmo_epdg_ipa_client_t *client, struct msgb *pdu);

/**
 * IP Access Protocol
 */
struct osmo_epdg_ipa_client_t {
	/**
	 * Register a callback to invoke when a IPA PDU of proto arrived.
	 *
	 * Only called when a full PDU has arrived.
	 *
	 * @param cb		callback function, NULL to unregister
	 * @param data		data to pass to callback
	 */
	int (*on_recv)(osmo_epdg_ipa_client_t *this, uint8_t osmo_proto, ipa_cb_t cb, void *data);

	/**
	 * Send a PDU over the IPA connection
	 *
	 * @param proto		define the protocol
	 * @param buf		data buffer to write
	 * @param len		number of bytes to write
	 * @return			number of bytes written, -1 on error
	 */
	ssize_t (*send)(osmo_epdg_ipa_client_t *this, uint8_t osmo_proto, struct msgb *msg);

	int (*on_error)(osmo_epdg_ipa_client_t *this, uint8_t osmo_proto, ipa_cb_t cb, void *data);

	// TODO: unsure if we need this int (*connect)(osmo_epdg_ipa_client_t *this);
	int (*disconnect)(osmo_epdg_ipa_client_t *this);
	/**
	 * Destroy a osmo_epdg_ipa_client_t.
	 */
	void (*destroy)(osmo_epdg_ipa_client_t *this);
};

/**
 * Create a osmo_epdg_ipa_client instance.
 *
 * @param address   the address of the gsup server */
osmo_epdg_ipa_client_t *osmo_epdg_ipa_client_create(char *addr);

#endif /** OSMO_EPDG_IPA_CLIENT_H_ @}*/

