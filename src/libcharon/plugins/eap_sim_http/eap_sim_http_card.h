/*
 * Copyright (C) 2025 Your Name
 */

#ifndef EAP_SIM_HTTP_CARD_H_
#define EAP_SIM_HTTP_CARD_H_

#include <simaka_card.h>

typedef struct eap_sim_http_card_t eap_sim_http_card_t;

struct eap_sim_http_card_t {
    simaka_card_t card;
    void (*destroy)(eap_sim_http_card_t *this);
};

eap_sim_http_card_t *eap_sim_http_card_create(void);

#endif /* EAP_SIM_HTTP_CARD_H_ */
