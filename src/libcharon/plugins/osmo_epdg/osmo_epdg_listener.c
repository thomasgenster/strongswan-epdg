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
#include <errno.h>
#include <unistd.h>

#include <osmocom/gsm/apn.h>

#include "osmo_epdg_plugin.h"
#include "osmo_epdg_listener.h"
#include "osmo_epdg_db.h"
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
	osmo_epdg_db_t *db;
};

METHOD(listener_t, eap_authorize, bool,
	private_osmo_epdg_listener_t *this, ike_sa_t *ike_sa,
	identification_t *id, bool final, bool *success)
{
	char imsi[16] = {0};
	osmo_epdg_ue_t *ue = NULL;

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

	ue = this->db->create_subscriber(this->db, ike_sa);
	if (!ue)
	{
		DBG1(DBG_NET, "epdg: authorize: Could not create subscriber via db! Rejecting.");
		goto err;
	}

	osmo_epdg_gsup_response_t *resp = this->gsup->update_location(this->gsup, imsi, OSMO_GSUP_CN_DOMAIN_PS);
	if (!resp)
	{
		DBG1(DBG_NET, "epdg: GSUP: couldn't send Update Location.");
		this->db->remove_subscriber(this->db, imsi);
		goto err;
	}

	if (resp->gsup.message_type != OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT)
	{
		DBG1(DBG_NET, "epdg_listener: Update Location Error! Cause: %02x", resp->gsup.cause);
		goto err;
	}
	ue->set_state(ue, UE_LOCATION_UPDATED);
	ue->put(ue);
	return TRUE;

err:
	*success = FALSE;
	if (ue)
	{
		ue->set_state(ue, UE_FAIL);
		ue->put(ue);
	}

	/* keep still subscribed */
	return TRUE;
}

METHOD(listener_t, authorize, bool,
	private_osmo_epdg_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	identification_t* imsi_id;
	char imsi[16] = {0};
	osmo_epdg_ue_t *ue = NULL;
	host_t *address = NULL;
	struct osmo_gsup_pdp_info *pdp_info;
	osmo_epdg_gsup_response_t *resp = NULL;


	DBG1(DBG_NET, "Authorized: uniq 0x%08x, name %s final: %d, eap: %d!",
		ike_sa->get_unique_id(ike_sa),
                ike_sa->get_name(ike_sa),
		final,
		ike_sa->has_condition(ike_sa, COND_EAP_AUTHENTICATED));

	if (!final)
	{
		return TRUE;
	}

	imsi_id = ike_sa->get_other_id(ike_sa);
	if (!imsi_id)
	{
		DBG1(DBG_NET, "epdg: authorize: Can't get EAP identity.");
		goto err;
	}

	if (get_imsi(imsi_id, imsi, sizeof(imsi) - 1))
	{
		DBG1(DBG_NET, "epdg: authorize: Can't find IMSI in EAP identity.");
		goto err;
	}

	ue = this->db->get_subscriber(this->db, imsi);
	if (!ue)
	{
		DBG1(DBG_NET, "epdg: authorize: Can't find match UE for imsi %s via EAP identity.", imsi);
	}

	ue->set_state(ue, UE_WAIT_TUNNEL);
	resp = this->gsup->tunnel_request(this->gsup, imsi);
	if (!resp)
	{
		DBG1(DBG_NET, "epdg_listener: Tunnel Request: GSUP: couldn't send.");
		goto err;
	}

	if (resp->gsup.message_type == OSMO_GSUP_MSGT_EPDG_TUNNEL_ERROR)
	{
		DBG1(DBG_NET, "epdg_listener: Tunnel Error! Cause: %02x", resp->gsup.cause);
		goto err;
	}
	else if (resp->gsup.message_type != OSMO_GSUP_MSGT_EPDG_TUNNEL_RESULT)
	{
		DBG1(DBG_NET, "epdg_listener: Tunnel Response: unexpected message type: %02x", resp->gsup.message_type);
		goto err;
	}

	/* validate Tunnel Response */
	if ((resp->gsup.num_pdp_infos != 1) ||
	    (!resp->gsup.pdp_infos[0].have_info) ||
	    (resp->gsup.pdp_infos[0].pdp_type_org != PDP_TYPE_ORG_IETF) ||
	    (resp->gsup.pdp_infos[0].pdp_type_nr != PDP_TYPE_N_IETF_IPv4))
	{
		DBG1(DBG_NET, "epdg_listener: Tunnel Response: IMSI %s: received incomplete message/wrong content", imsi);
		goto err;
	}

	pdp_info = &resp->gsup.pdp_infos[0];
	/* if the sa_family is set, the address is valid */
	if (pdp_info->pdp_address[0].u.sa.sa_family != AF_INET)
	{
		DBG1(DBG_NET, "epdg_listener: Tunnel Response: IMSI %s: received wrong PDP info", imsi);
		goto err;
	}

	address = host_create_from_sockaddr(&pdp_info->pdp_address[0].u.sa);
	if (!address)
	{
		DBG1(DBG_NET, "epdg_listener: Tunnel Response: IMSI %s: couldn't convert PDP info to host_address", imsi);
		goto err;
	}

	ue->set_address(ue, address);
	ue->set_state(ue, UE_TUNNEL_READY);
	ue->put(ue);

	address->destroy(address);
	free(resp);
	return TRUE;

err:

	if (resp)
	{
		free(resp);
	}

	if (ue)
	{
		ue->set_state(ue, UE_FAIL);
		ue->put(ue);
	}
	DESTROY_IF(address);

	*success = FALSE;
	/* keep still subscribed */
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
       private_osmo_epdg_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	char imsi[16] = {0};
	if (get_imsi_ike(ike_sa, imsi, sizeof(imsi)))
	{
		DBG1(DBG_NET, "epdg_listener: updown: imsi UNKNOWN: IKE_SA went %s", up ? "up" : "down");
		return TRUE;
	}
	DBG1(DBG_NET, "epdg_listener: updown: imsi %s: IKE_SA went %s", imsi, up ? "up" : "down");

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
osmo_epdg_listener_t *osmo_epdg_listener_create(osmo_epdg_db_t *db, osmo_epdg_gsup_client_t *gsup)
{
	private_osmo_epdg_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.authorize = _authorize,
				.eap_authorize = _eap_authorize,
				.ike_updown = _ike_updown,
			},
			.destroy = _destroy,
		},
		.gsup = gsup,
		.db = db,
	);

	return &this->public;
}
