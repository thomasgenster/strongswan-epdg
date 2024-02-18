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

#include <errno.h>

#include <sa/ike_sa.h>
#include <threading/rwlock.h>
#include <utils/utils.h>
#include <utils/debug.h>

#include "osmo_epdg_ue.h"
#include "osmo_epdg_utils.h"

typedef struct private_osmo_epdg_ue_t private_osmo_epdg_ue_t;


/**
 * Private data of an osmo_epdg_ue_t object.
 */
struct private_osmo_epdg_ue_t {
	/**
	 * Public osmo_epdg_ue_t interface.
	 */
	osmo_epdg_ue_t public;

	/**
	 * a unique id.
	 * Same as ike_sa_t->get_unique_id().
	 */
	uint32_t id;

	/**
	 * IMSI encoded as character
	 */
	char *imsi;

	/**
	 * APN encoded as character (foo.example)
	 */
	char *apn;

	/**
	 * IP address of the client. Might become a llist_t in the future
	 */
	host_t *address;

	/**
	 * Refcount to track this object.
	 * It will call destroy() when refcount reaches 0
	 */
	refcount_t refcount;

	/**
	 * rwlock to lock access for changes
	 */
	rwlock_t *lock;

	enum osmo_epdg_ue_state state;
};

METHOD(osmo_epdg_ue_t, get_imsi, const char *,
       private_osmo_epdg_ue_t *this)
{
	return this->imsi;
}

METHOD(osmo_epdg_ue_t, get_apn, const char *,
       private_osmo_epdg_ue_t *this)
{
	return this->apn;
}

METHOD(osmo_epdg_ue_t, get_id, uint32_t,
       private_osmo_epdg_ue_t *this)
{
	return this->id;
}

METHOD(osmo_epdg_ue_t, set_id, void,
       private_osmo_epdg_ue_t *this, uint32_t unique_id)
{
	this->id = unique_id;
}

METHOD(osmo_epdg_ue_t, set_address, void,
       private_osmo_epdg_ue_t *this, host_t *address)
{
	this->lock->write_lock(this->lock);
	if (this->address)
	{
		this->address->destroy(this->address);
	}
	this->address = address->clone(address);
	this->lock->unlock(this->lock);
}

METHOD(osmo_epdg_ue_t, get_address, host_t *,
       private_osmo_epdg_ue_t *this)
{
	host_t *address = NULL;

	this->lock->read_lock(this->lock);
	if (this->address)
	{
		address = this->address->clone(this->address);
	}
	this->lock->unlock(this->lock);

	return address;
}

METHOD(osmo_epdg_ue_t, set_state, void,
       private_osmo_epdg_ue_t *this, enum osmo_epdg_ue_state state)
{
	this->lock->write_lock(this->lock);
	/* TODO: implement a FSM. At least we can get debug information out of it. */
	this->state = state;
	this->lock->unlock(this->lock);
}

METHOD(osmo_epdg_ue_t, get_state, enum osmo_epdg_ue_state,
       private_osmo_epdg_ue_t *this)
{
	enum osmo_epdg_ue_state state;
	this->lock->read_lock(this->lock);
	/* TODO: implement a FSM. At least we can get debug information out of it. */
	state = this->state;
	this->lock->unlock(this->lock);

	return state;
}

METHOD(osmo_epdg_ue_t, get, void,
       private_osmo_epdg_ue_t *this)
{
	ref_get(&this->refcount);
}

METHOD(osmo_epdg_ue_t, put, void,
       private_osmo_epdg_ue_t *this)
{
	if (ref_put(&this->refcount))
	{
		this->public.destroy(&this->public);
	}
}

METHOD(osmo_epdg_ue_t, destroy, void,
       private_osmo_epdg_ue_t *this)
{
	this->lock->destroy(this->lock);
	free(this->apn);
	free(this->imsi);
	free(this);
}

osmo_epdg_ue_t *osmo_epdg_ue_create(uint32_t id, const char *imsi, const char *apn)
{
	private_osmo_epdg_ue_t *this;

	if (epdg_validate_apn(apn) ||
	    epdg_validate_imsi(imsi))
	{
		return NULL;
	}

	INIT(this,
	     .public = {
		 .get = _get,
		 .put = _put,
		 .get_apn = _get_apn,
		 .get_imsi = _get_imsi,
		 .get_id = _get_id,
		 .set_id = _set_id,
		 .get_address = _get_address,
		 .set_address = _set_address,
		 .get_state = _get_state,
		 .set_state = _set_state,
		 .destroy = _destroy,
	     },
	     .apn = strdup(apn),
	     .imsi = strdup(imsi),
	     .id = id,
	     .lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	     .state = UE_WAIT_LOCATION_UPDATE,
	     .refcount = 1,
	     );

	return &this->public;
}
