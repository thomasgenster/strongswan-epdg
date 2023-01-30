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

#include "osmo_epdg_plugin.h"
#include "osmo_epdg_provider.h"
#include "osmo_epdg_listener.h"

typedef struct private_osmo_epdg_t private_osmo_epdg_t;

/**
 * Private data of an eap_osmo_epdg_t object.
 */
struct private_osmo_epdg_t {
	/**
	 * Public osmo_epdg_plugin_t interface.
	 */
	osmo_epdg_plugin_t public;

	/**
	 * SIM AKA provider
	 */
	osmo_epdg_provider_t *provider;

	osmo_epdg_listener_t *listener;
};

METHOD(plugin_t, get_name, char*,
	private_osmo_epdg_t *this)
{
	return "osmo-epdg";
}

static bool register_functions(private_osmo_epdg_t *this,
							   plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		osmo_epdg_gsup_client_t *gsup = osmo_epdg_gsup_client_create("tcp://127.0.0.1:4222");
		this->provider = osmo_epdg_provider_create(gsup);
		this->listener = osmo_epdg_listener_create(gsup);
		charon->bus->add_listener(charon->bus, &this->listener->listener);
		return TRUE;
	}
	if (this->listener)
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
	}
	this->provider->destroy(this->provider);
	this->provider = NULL;
	return TRUE;
}

/**
 * Callback providing our provider to register
 */
static simaka_provider_t* get_provider(private_osmo_epdg_t *this)
{
	return &this->provider->provider;
}

METHOD(plugin_t, get_features, int,
	private_osmo_epdg_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((void*)register_functions, NULL),
			PLUGIN_PROVIDE(CUSTOM, "osmo-epdg"),
		PLUGIN_CALLBACK(simaka_manager_register, get_provider),
			PLUGIN_PROVIDE(CUSTOM, "aka-provider"),
				PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_osmo_epdg_t *this)
{
	free(this);
}

/**
 * See header
 */
plugin_t *osmo_epdg_plugin_create()
{
	private_osmo_epdg_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

