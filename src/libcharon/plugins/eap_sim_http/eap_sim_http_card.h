#ifndef EAP_SIM_HTTP_CARD_H_
#define EAP_SIM_HTTP_CARD_H_

#include <simaka_card.h>

typedef struct eap_sim_http_card_t eap_sim_http_card_t;

/**
 * SIM card implementation using a HTTP server.
 */
struct eap_sim_http_card_t {

    /**
     * Implements simaka_card_t interface
     */
    simaka_card_t card;

    /**
     * Destroy a eap_sim_http_card_t.
     */
    void (*destroy)(eap_sim_http_card_t *this);
};

/**
 * Create a eap_sim_http_card instance.
 */
eap_sim_http_card_t *eap_sim_http_card_create();

#endif /** EAP_SIM_HTTP_CARD_H_ @}*/
