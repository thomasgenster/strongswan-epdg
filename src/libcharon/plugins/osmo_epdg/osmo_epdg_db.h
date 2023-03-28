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
 * @defgroup osmo_epdg_db osmo_epdg_db
 * @{ @ingroup osmo_epdg
 */

#ifndef OSMO_EPDG_LISTENER_H_
#define OSMO_EPDG_LISTENER_H_

#include <bus/listeners/listener.h>
#include "gsup_client.h"

typedef struct osmo_epdg_db_t osmo_epdg_db_t;

/**
 * SIM listener implementation using a set of AKA functions.
 */
struct osmo_epdg_db_t {
	/**
	 * Create new subscriber by imsi, before sending authentication
	 */
	osmo_epdg_ue_t *(*create_subscriber_imsi)(osmo_epdg_db_t *this, ike_sa_t *ike_sa, char *imsi);

	/**
	 * Get subscriber by imsi, there might be multiple UE by this IMSI
	 */
	osmo_epdg_ue_t *(*get_subscriber_imsi)(osmo_epdg_db_t *this, char *imsi, int offset);

	/**
	 * Get subscriber by id
	 */
	osmo_epdg_ue_t *(*get_subscriber_id)(osmo_epdg_db_t *this, uint32_t id);

	/**
	 * Destroy subscriber by imsi
	 */
	void (*destroy_subscriber_id)(osmo_epdg_db_t *this, uint32_t id);

	/**
	 * Destroy subscriber by object
	 */
	void (*destroy_subscriber)(osmo_epdg_db_t *this, osmo_epdg_ue_t *ue);

	/**
	 * Destroy a osmo_epdg_db_t.
	 */
	void (*destroy)(osmo_epdg_db_t *this);
};

/**
 * Create a osmo_epdg_db instance.
 */
osmo_epdg_db_t *osmo_epdg_db_create(osmo_epdg_gsup_client_t *gsup);

#endif /** OSMO_EPDG_LISTENER_H_ @}*/
