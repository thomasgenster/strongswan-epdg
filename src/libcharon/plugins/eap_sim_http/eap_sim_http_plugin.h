/*
 * Copyright (C) 2025 Your Name
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#ifndef EAP_SIM_HTTP_PLUGIN_H_
#define EAP_SIM_HTTP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_sim_http_plugin_t eap_sim_http_plugin_t;

struct eap_sim_http_plugin_t {
    plugin_t plugin;
};

plugin_t *eap_sim_http_plugin_create(void);

#endif /* EAP_SIM_HTTP_PLUGIN_H_ */
