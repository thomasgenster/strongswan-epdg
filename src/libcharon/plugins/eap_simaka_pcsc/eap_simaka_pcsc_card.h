/*
 * Copyright (C) 2017 Domonkos P. Tomcsanyi
 * umlaut Communications Gmbh.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef EAP_SIMAKA_PCSC_CARD_H_
#define EAP_SIMAKA_PCSC_CARD_H_

#include <simaka_card.h>

typedef struct eap_simaka_pcsc_card_t eap_simaka_pcsc_card_t;

/**
 * SIM card implementing PC/SC backend.
 */
struct eap_simaka_pcsc_card_t {

	/**
	 * Implements simaka_card_t interface
	 */
	simaka_card_t card;

	/**
	 * Destroy a eap_simaka_pcsc_card_t.
	 */
	void (*destroy)(eap_simaka_pcsc_card_t *this);
};

/**
 * Create a eap_simaka_pcsc_card instance.
 */
eap_simaka_pcsc_card_t *eap_simaka_pcsc_card_create();

#endif /** EAP_SIMAKA_PCSC_CARD_H_ @}*/
