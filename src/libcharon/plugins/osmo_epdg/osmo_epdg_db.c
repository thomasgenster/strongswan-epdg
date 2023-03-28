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

#include <daemon.h>
#include <plugins/plugin.h>
#include <collections/hashtable.h>
#include <unistd.h>

#include "osmo_epdg_plugin.h"
#include "osmo_epdg_db.h"
#include "osmo_epdg_utils.h"

typedef struct private_osmo_epdg_db_t private_osmo_epdg_db_t;

/**
 * Private data of an osmo_epdg_db_t object.
 */
struct private_osmo_epdg_db_t {
	/**
	 * Public osmo_epdg_db_t interface.
	 */
	osmo_epdg_db_t public;

	/**
	 * GSUP client
	 */
	osmo_epdg_gsup_client_t *gsup;

	/**
	 * subscriber hash by ID
	 */
	hashtable_t *subscribers;

	/**
	 * subscriber hash by imsi (how to handle multiple?)
	 */
	hashtable_t *subscribers_imsi;

	/**
	 * subscriber by ike_sa
	 */
	hashtable_t *subscribers_ike_sa_t;
};

METHOD(osmo_epdg_db_t, create_subscriber_imsi, osmo_epdg_ue_t *,
	private_osmo_epdg_db_t *this, ike_sa_t *ike_sa,
	char *imsi)
{
	return NULL;
}

METHOD(osmo_epdg_db_t, get_subscriber_imsi, osmo_epdg_ue_t *,
	private_osmo_epdg_db_t *this, char *imsi, int offset)
{
	return NULL;
}

METHOD(osmo_epdg_db_t, get_subscriber_id, osmo_epdg_ue_t *,
	private_osmo_epdg_db_t *this, uint32_t id)
{
	return NULL;
}

METHOD(osmo_epdg_db_t, get_subscriber_ike, osmo_epdg_ue_t *,
	private_osmo_epdg_db_t *this, ike_sa_t *ike_sa)
{
	return NULL;
}

METHOD(osmo_epdg_db_t, destroy_subscriber_id, void,
	private_osmo_epdg_db_t *this, uint32_t id)
{
	return;
}

METHOD(osmo_epdg_db_t, destroy_subscriber_ike, void,
	private_osmo_epdg_db_t *this, ike_sa_t *ike_sa)
{
	return;
}

METHOD(osmo_epdg_db_t, destroy_subscriber, void,
	private_osmo_epdg_db_t *this, osmo_epdg_ue_t *ue)
{
	return;
}

METHOD(osmo_epdg_db_t, destroy, void,
	private_osmo_epdg_db_t *this)
{
	free(this);
}

/**
 * See header
 */
osmo_epdg_db_t *osmo_epdg_db_create(osmo_epdg_gsup_client_t *gsup)
{
	private_osmo_epdg_db_t *this;

	INIT(this,
		.public = {
			.create_subscriber = _create_subscriber_imsi,
			.get_subscriber_id = _get_subscriber_id,
			.get_subscriber_imsi = _get_subscriber_imsi,
			.get_subscriber_ike = _get_subscriber_ike,
			.destroy_subscriber_ike = _destroy_subscriber_ike,
			.destroy_subscriber_id = _destroy_subscriber_id,
			.destroy_subscriber = _destroy_subscriber,
			.destroy = _destroy,
		},
	);

	return &this->public;
}

