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

#ifndef OSMO_EPDG_DB_H_
#define OSMO_EPDG_DB_H_

#include <bus/listeners/listener.h>
#include "gsup_client.h"
#include "osmo_epdg_ue.h"
#include "osmo_epdg_utils.h"

typedef struct osmo_epdg_db_t osmo_epdg_db_t;

/**
 * DB object to store state across different threads.
 */
struct osmo_epdg_db_t {
	/**
	 * Create new subscriber by imsi, before sending authentication.
	 * NULL or UE object. The UE object need to called put() when not used.
	 */
	osmo_epdg_ue_t *(*create_subscriber)(osmo_epdg_db_t *this, ike_sa_t *ike_sa);

	/**
	 * Get subscriber by imsi, there might be multiple UE by this IMSI
	 * NULL or UE object. The UE object need to called put() when not used.
	 */
	osmo_epdg_ue_t *(*get_subscriber)(osmo_epdg_db_t *this, char *imsi);

	/**
	 * Get subscriber by imsi via ike_sa, there might be multiple UE by this IMSI
	 * NULL or UE object. The UE object need to called put() when not used.
	 */
	osmo_epdg_ue_t *(*get_subscriber_ike)(osmo_epdg_db_t *this, ike_sa_t *ike_sa);

	/**
	 * Remove a subscriber from the db.
	 */
	void (*remove_subscriber)(osmo_epdg_db_t *this, const char *imsi);

	/**
	 * Destroy a osmo_epdg_db_t.
	 */
	void (*destroy)(osmo_epdg_db_t *this);
};

/**
 * Create a osmo_epdg_db instance.
 */
osmo_epdg_db_t *osmo_epdg_db_create();

#endif /* OSMO_EPDG_DB_H_ */
