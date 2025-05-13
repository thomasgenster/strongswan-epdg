#ifndef EAP_SIM_HTTP_PLUGIN_H_
#define EAP_SIM_HTTP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_sim_http_plugin_t eap_sim_http_plugin_t;

/**
 * Plugin to provide a SIM card from a HTTP server.
 */
struct eap_sim_http_plugin_t {

    /**
     * implements plugin interface
     */
    plugin_t plugin;
};

#endif /** EAP_SIM_HTTP_PLUGIN_H_ @}*/
