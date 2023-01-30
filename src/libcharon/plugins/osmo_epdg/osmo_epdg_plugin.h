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
 * @defgroup eap_osmo_epdg eap_aka_3gpp2
 * @ingroup cplugins
 *
 * @defgroup eap_osmo_epdg_plugin eap_aka_3gpp2_plugin
 * @{ @ingroup eap_osmo_epdg
 */

#ifndef OSMO_EPDG_PLUGIN_H_
#define OSMO_EPDG_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct osmo_epdg_plugin_t osmo_epdg_plugin_t;

struct osmo_epdg_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** OSMO_EPDG_PLUGIN_H_ @}*/
