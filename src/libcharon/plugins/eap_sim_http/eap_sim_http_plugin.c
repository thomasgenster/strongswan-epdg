#include "eap_sim_http_plugin.h"
#include "eap_sim_http_card.h"

#include <daemon.h>

typedef struct private_eap_sim_http_plugin_t private_eap_sim_http_plugin_t;

/**
 * Private data of an eap_sim_http_t object.
 */
struct private_eap_sim_http_plugin_t {

    /**
     * Public eap_sim_http_plugin_t interface.
     */
    eap_sim_http_plugin_t public;

    /**
     * SIM card
     */
    eap_sim_http_card_t *card;
};

METHOD(plugin_t, get_name, char*,
    private_eap_sim_http_plugin_t *this)
{
    return "eap-sim-http";
}

/**
 * Callback providing our card to register
 */
static simaka_card_t* get_card(private_eap_sim_http_plugin_t *this)
{
    return &this->card->card;
}

METHOD(plugin_t, get_features, int,
    private_eap_sim_http_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        PLUGIN_CALLBACK(simaka_manager_register, get_card),
            PLUGIN_PROVIDE(CUSTOM, "aka-card"),
                PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
            PLUGIN_PROVIDE(CUSTOM, "sim-card"),
                PLUGIN_DEPENDS(CUSTOM, "sim-manager"),
    };
    *features = f;
    return countof(f);
}

METHOD(plugin_t, destroy, void,
    private_eap_sim_http_plugin_t *this)
{
    this->card->destroy(this->card);
    free(this);
}

/**
 * See header
 */
plugin_t *eap_sim_http_plugin_create()
{
    private_eap_sim_http_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
        .card = eap_sim_http_card_create(),
    );

    return &this->public.plugin;
}
