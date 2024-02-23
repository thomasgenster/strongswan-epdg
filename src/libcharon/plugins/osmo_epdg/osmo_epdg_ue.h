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
	 * Get APN
	 * Should not change.
	 */
	const char *(*get_apn)(osmo_epdg_ue_t *this);

	/**
	 * Get IMSI
	 * Should not change.
	 */
	const char *(*get_imsi)(osmo_epdg_ue_t *this);

	/**
	 * Get unique ID
	 * The unique ID may change either by reconnect or rekey
	 */
	uint32_t (*get_id)(osmo_epdg_ue_t *this);

	/**
	 * Get unique ID
	 * The unique ID may change either by reconnect or rekey
	 */
	void (*set_id)(osmo_epdg_ue_t *this, uint32_t unique_id);

	/**
	 * Get Linked list of osmo_epdg_attribute_t
	 */
	linked_list_t *(*get_attributes)(osmo_epdg_ue_t *this);

	/**
	 * The attributes the UE requested. Pass ike->create_attribute_enumerator() towards it.
	 * An enumerator(configuration_attribute_type_t, chunk_t, bool).
	 * The enumerator will be destroyed by request_attributes.
	 */
	int (*fill_request_attributes)(osmo_epdg_ue_t *this, enumerator_t *enumerator);

	/**
	 * Get PCO encoded elements. It will return attributes encoded as PCO.
	 * On error returns != 0.
	 * On success, the caller must free *pco.
	 */
	int (*generate_pco)(osmo_epdg_ue_t *this, char **pco, uint8_t *pco_len);

	/**
	 * Get PCO encoded elements. It will return attributes encoded as PCO.
	 * On error returns != 0.
	 * On success, the caller must free *pco.
	 */
	int (*convert_pco)(osmo_epdg_ue_t *this, const uint8_t *pco, uint8_t pco_len);

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

struct osmo_epdg_attribute_t {
	configuration_attribute_type_t type;
	chunk_t value;
	bool valid;
};
typedef struct osmo_epdg_attribute_t osmo_epdg_attribute_t;

/**
 * Create a osmo_epdg_ue instance.
 * A newly created object will come with refcount = 1. Use put() to destroy it.
 */
osmo_epdg_ue_t *osmo_epdg_ue_create(uint32_t id, const char *imsi, const char *apn);

#endif /* OSMO_EPDG_UE_H_ */
