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

#include <daemon.h>
#include <plugins/plugin.h>
#include <unistd.h>

#include "osmo_epdg_plugin.h"
#include "osmo_epdg_listener.h"
#include "osmo_epdg_utils.h"

typedef struct private_osmo_epdg_listener_t private_osmo_epdg_listener_t;

/**
 * Private data of an osmo_epdg_listener_t object.
 */
struct private_osmo_epdg_listener_t {
	/**
	 * Public osmo_epdg_listener_t interface.
	 */
	osmo_epdg_listener_t public;

	osmo_epdg_gsup_client_t *gsup;
};

METHOD(listener_t, eap_authorize, bool,
	private_osmo_epdg_listener_t *this, ike_sa_t *ike_sa,
	identification_t *id, bool final, bool *success)
{
	char imsi[16] = {0};

	if (!id)
	{
		DBG1(DBG_NET, "epdg: authorize: no id given. Failing.");
		goto err;
	}
	if (get_imsi(id, imsi, sizeof(imsi) - 1))
	{
		DBG1(DBG_NET, "epdg: authorize: Can't find IMSI in EAP identity.");
		goto err;
	}

	osmo_epdg_gsup_response_t *resp = this->gsup->update_location(this->gsup, imsi, OSMO_GSUP_CN_DOMAIN_PS);
	if (!resp)
	{
		DBG1(DBG_NET, "epdg: GSUP: couldn't send Update Location.");
		goto err;
	}

	if (resp->gsup.message_type != OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT)
	{
		DBG1(DBG_NET, "epdg_listener: Update Location Error! Cause: %02x", resp->gsup.cause);
		goto err;
	}

	return TRUE;

err:
	*success = FALSE;
	/* keep still subscribed */
	return TRUE;
}

METHOD(listener_t, authorize, bool,
	private_osmo_epdg_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	DBG1(DBG_NET, "Authorized: uniq 0x%08x, name %s final: %d, eap: %d!",
		ike_sa->get_unique_id(ike_sa),
                ike_sa->get_name(ike_sa),
		final,
		ike_sa->has_condition(ike_sa, COND_EAP_AUTHENTICATED));
	
	sleep(1);
	if (final)
	{
		/* TODO: create new Tunnel and save Tunnel information locally */
	}
	return TRUE;
}

METHOD(osmo_epdg_listener_t, destroy, void,
	private_osmo_epdg_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
osmo_epdg_listener_t *osmo_epdg_listener_create(osmo_epdg_gsup_client_t *gsup)
{
	private_osmo_epdg_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.authorize = _authorize,
				.eap_authorize = _eap_authorize,
			},
			.destroy = _destroy,
		},
		.gsup = gsup,
	);

	return &this->public;
}
