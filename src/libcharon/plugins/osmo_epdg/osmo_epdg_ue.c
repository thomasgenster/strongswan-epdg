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
#include <collections/linked_list.h>
#include <utils/utils.h>
#include <utils/debug.h>

#include "pco.h"
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
	 * The requested attributes/PCO options on GTP
	 * e.g. P-CSCF requests, DNS, ..
	 * holds attribute_entry_t
	 */
	linked_list_t *request_attributes;

	/**
	 * The response attributes/PCO options on GTP
	 * e.g. P-CSCF requests, DNS, ..
	 * holds attribute_entry_t
	 */
	linked_list_t *response_attributes;

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

METHOD(osmo_epdg_ue_t, get_attributes, linked_list_t *,
       private_osmo_epdg_ue_t *this)
{
	/* TODO: check if we need to also take locking .. also refcounting would be great here */
	return this->response_attributes;
}

/* Fill all request_attributes into the UE object to generate PCO later out of it */
METHOD(osmo_epdg_ue_t, fill_request_attributes, int,
       private_osmo_epdg_ue_t *this, enumerator_t *enumerator)
{
	configuration_attribute_type_t type;
	chunk_t chunk;
	bool handled;
	osmo_epdg_attribute_t *entry;

	if (!enumerator)
	{
		return -EINVAL;
	}

	while (enumerator->enumerate(enumerator, &type, &chunk, &handled))
	{
		INIT(entry,
			.type = type,
			.value = chunk_empty,
			.valid = FALSE,
		);
		this->request_attributes->insert_last(this->request_attributes, entry);
	}
	enumerator->destroy(enumerator);

	return 0;
}

/* requires a enumerator from attributes. The enumerator left intact. */
static int count_pcos(enumerator_t *enumerator)
{
	osmo_epdg_attribute_t *entry;
	int count = 0;

	while (enumerator->enumerate(enumerator, (void **) &entry))
	{
		switch (entry->type)
		{
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP6_DNS:
		case P_CSCF_IP4_ADDRESS:
		case P_CSCF_IP6_ADDRESS:
			count++;
			break;
		default:
			break;
		}
	}

	return count;
}

static inline int encode_pco_req(char *data, enum pco_protocols pco_protocol)
{
	struct pco_element pco = { .length = 0 };
	pco.protocol_id = htons(pco_protocol);
	memcpy(data, &pco, sizeof(struct pco_element));
	return sizeof(struct pco_element);
}

#define MAX_PCO_LEN 251

METHOD(osmo_epdg_ue_t, generate_pco, int,
       private_osmo_epdg_ue_t *this, char **pco, uint8_t *pco_len)
{
	enumerator_t *enumerator;
	osmo_epdg_attribute_t *entry;
	int pcos_num;
	size_t max_size;
	uint8_t iter = 0;

	if (!pco || !pco_len)
	{
		return -EINVAL;
	}

	enumerator = this->request_attributes->create_enumerator(this->request_attributes);
	if (!enumerator)
	{
		return -EBUSY;
	}

	pcos_num = count_pcos(enumerator);
	if (pcos_num == 0)
	{
		*pco = NULL;
		*pco_len = 0;
		enumerator->destroy(enumerator);
		return 0;
	}

	/* 3GPP TS 10.5.6.3: Encode here octet 3 - ZA
	 * Octet: 3 as header
	 * a PCO with zero length requires 3 bytes. zero length because we request it
	 */
	max_size = 1 + pcos_num * 3;
	if (max_size > MAX_PCO_LEN)
	{
		enumerator->destroy(enumerator);
		return -E2BIG;
	}

	*pco = calloc(1, 1 + pcos_num * 3);
	this->request_attributes->reset_enumerator(this->request_attributes, enumerator);

	/* Config protocol: 0x00 + Ext bit = 0x80 */
	iter = 0;
	(*pco)[iter++] = 0x80;

	while (enumerator->enumerate(enumerator, (void **) &entry))
	{
		switch (entry->type)
		{
			case P_CSCF_IP6_ADDRESS:
				iter += encode_pco_req(*pco + iter, PCO_P_PCSCF_ADDR);
				break;
			case INTERNAL_IP6_DNS:
				iter += encode_pco_req(*pco + iter, PCO_P_DNS_IPv6_ADDR);
				break;
			case P_CSCF_IP4_ADDRESS:
				iter += encode_pco_req(*pco + iter, PCO_P_PCSCF_IPv4_ADDR);
				break;
			case INTERNAL_IP4_DNS:
				iter += encode_pco_req(*pco + iter, PCO_P_DNS_IPv4_ADDR);
				break;
			default:
				break;
		}
	}
	*pco_len = iter;
	enumerator->destroy(enumerator);

	return 0;
}

/* Fill the attribute of type *type* with the value, len
 */
static void set_attribute(private_osmo_epdg_ue_t *this,
		  configuration_attribute_type_t type, const char *value, uint8_t len)
{
	osmo_epdg_attribute_t *entry;

	INIT(entry,
		.type = type,
		.value = chunk_clone(chunk_create((char *) value, len)),
		.valid = TRUE,
	);
	this->response_attributes->insert_last(this->response_attributes, entry);
}

/* Take the PCO response from the PGW and fill the attributes */
METHOD(osmo_epdg_ue_t, convert_pco, int,
       private_osmo_epdg_ue_t *this, const uint8_t *pco, uint8_t pco_len)
{
	int iter = 0;
	uint16_t a_pco = 0;
	uint8_t a_pco_len = 0;
	const char *value;

	if (pco_len == 0)
	{
		return 0;
	}

	if (!pco)
	{
		return -EINVAL;
	}

	if (pco[iter++] != 0x80)
	{
		return -EBADF;
	}

	/* first run validate length of TLVs */
	while (iter + 2 < pco_len)
	{
		/* Skip Type field */
		iter += 2;
		/* uint8_t length field */
		iter += (uint8_t) pco[iter] + 1;
	}

	/* TLV doesn't add up. Either additional data or not enough data */
	if (iter != pco_len)
	{
		return -EFBIG;
	}
	iter = 1;

	/* second run parse known TLVs */
	while (iter + 2 < pco_len)
	{
		a_pco = pco[iter] << 8 | pco[iter + 1];
		a_pco_len = pco[iter + 2];

		/* header size + value */
		iter += 3 + a_pco_len;
		/* we ignore empty PCO */
		if (!a_pco_len)
		{
			continue;
		}

		value = (const char *) &pco[iter + 3];
		switch (a_pco)
		{
			case PCO_P_PCSCF_IPv4_ADDR:
				set_attribute(this, P_CSCF_IP4_ADDRESS, value, a_pco_len);
				break;
			case PCO_P_PCSCF_ADDR: /* IPv6 */
				set_attribute(this, P_CSCF_IP6_ADDRESS, value, a_pco_len);
				break;
			case PCO_P_DNS_IPv4_ADDR:
				set_attribute(this, INTERNAL_IP4_DNS, value, a_pco_len);
				break;
			case PCO_P_DNS_IPv6_ADDR:
				set_attribute(this, INTERNAL_IP6_DNS, value, a_pco_len);
				break;
		}
	}

	return 0;
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


CALLBACK(destroy_attribute, void,
	osmo_epdg_attribute_t *attr)
{
	if (attr->valid)
	{
		chunk_free(&attr->value);
	}
	free(attr);
}

METHOD(osmo_epdg_ue_t, destroy, void,
       private_osmo_epdg_ue_t *this)
{
	this->lock->destroy(this->lock);
	this->request_attributes->destroy_function(this->request_attributes, destroy_attribute);
	this->response_attributes->destroy_function(this->response_attributes, destroy_attribute);

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
		 .get_attributes = _get_attributes,
		 .fill_request_attributes = _fill_request_attributes,
		 .generate_pco = _generate_pco,
		 .convert_pco = _convert_pco,
		 .destroy = _destroy,
	     },
	     .apn = strdup(apn),
	     .imsi = strdup(imsi),
	     .id = id,
	     .lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	     .state = UE_WAIT_LOCATION_UPDATE,
	     .request_attributes = linked_list_create(),
	     .response_attributes = linked_list_create(),
	     .refcount = 1,
	     );

	return &this->public;
}
