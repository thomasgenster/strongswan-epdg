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

#include <osmocom/core/msgb.h>
#include <utils/utils.h>
#include <utils/debug.h>

#include "osmo_epdg_utils.h"

struct msgb *chunk_to_msgb(chunk_t *chunk)
{
	struct msgb *msg;
	if (chunk->len < sizeof(*msg))
	{
		return NULL;
	}

	msg = (struct msgb *) chunk->ptr;
	memset(msg, 0x00, sizeof(*msg));
	msg->data_len = chunk->len - sizeof(*msg);
	msg->len = 0;
	msg->data = msg->_data;
	msg->head = msg->_data;
	msg->tail = msg->_data;
	return msg;
}

int get_imsi(identification_t *id, char *imsi, size_t imsi_len)
{
	chunk_t nai = id->get_encoding(id);
	/* TODO: maybe use regex? */
	/* 099942123456789@mnc042.mcc999.3gpp... */
	if (nai.len < 17)
	{
		DBG1(DBG_NET, "epdg: Invalid NAI %s.", nai);
		return -EINVAL;
	}

	if (nai.ptr[0] != '0')
	{
		DBG1(DBG_NET, "epdg: Invalid NAI. Only support IMSI (starting with 0). %s.",
		 nai);
		return -EINVAL;
	}

	strncpy(imsi, nai.ptr + 1, min(15, imsi_len));
	return 0;
}
