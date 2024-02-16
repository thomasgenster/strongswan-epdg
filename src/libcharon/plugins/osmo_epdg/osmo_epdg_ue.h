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

#ifndef OSMO_EPDG_UE_H_
#define OSMO_EPDG_UE_H_

#include <stdint.h>
#include <networking/host.h>

/**
 * @defgroup osmo_epdg_ue osmo_epdg_ue
 * @{ @ingroup osmo_epdg
 */

typedef struct osmo_epdg_ue_t osmo_epdg_ue_t;

enum osmo_epdg_ue_state {
	/* Initial */
	UE_UNAUTHENTICATED,
	/* Authenticated */
	UE_AUTHENTICATED,
	/* Wait for GSUP Update Location Response */
	UE_WAIT_LOCATION_UPDATE,
	/* When the LOCATION UPDATE went successful */
	UE_LOCATION_UPDATED,
	/* Wait for GSUP Tunnel Response */
	UE_WAIT_TUNNEL,
	/* Tunnel Succeeded */
	UE_TUNNEL_READY,
	/* Everything ready, data can flow */
	UE_CONNECTED,
	/* Notify the osmo-epdg about destruction, wait for an answer */
	UE_DISCONNECTING,
	/* When the UE failed, but the IKE_SA hasn't been destroyed */
	UE_FAIL,
	UE_DESTROYED,
};

/**
 * UE object
 */
struct osmo_epdg_ue_t {
	/**
	 * Get IMSI
	 */
	const char *(*get_imsi)(osmo_epdg_ue_t *this);

	/**
	 * Get address. Returns NULL or a cloned' host_t object
	 */
	host_t *(*get_address)(osmo_epdg_ue_t *this);

	/**
	 * Set address. It will internally clone the given object.
	 */
	void (*set_address)(osmo_epdg_ue_t *this, host_t *address);

	/**
	 * Get state
	 */
	enum osmo_epdg_ue_state (*get_state)(osmo_epdg_ue_t *this);

	/**
	 * Set state
	 */
	void (*set_state)(osmo_epdg_ue_t *this, enum osmo_epdg_ue_state state);


	/**
	 * Increase the internal refcount. Use put() when done with the object
	 */
	void (*get)(osmo_epdg_ue_t *this);

	/**
	 * Decrease the internal refcount.
	 * When reaching zero, the object will be destroyed.
	 */
	void (*put)(osmo_epdg_ue_t *this);

	/**
	 * Destroy a osmo_epdg_db_t. Use get/put to track it. Don't use destroy().
	 * TODO: maybe remove destroy() completely.
	 */
	void (*destroy)(osmo_epdg_ue_t *this);
};

/**
 * Create a osmo_epdg_ue instance.
 * A newly created object will come with refcount = 1. Use put() to destroy it.
 */
osmo_epdg_ue_t *osmo_epdg_ue_create(uint32_t id, char *imsi);

#endif /* OSMO_EPDG_UE_H_ */
