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

#include <osmocom/core/msgb.h>
#include <sa/ike_sa.h>
#include <utils/chunk.h>
#include <utils/identification.h>


#define IPA_ALLOC_SIZE 1200

struct msgb *chunk_to_msgb(chunk_t *chunk);
int get_imsi(identification_t *id, char *imsi, size_t imsi_len);
int get_apn(ike_sa_t *sa, char *apn, size_t apn_len);
