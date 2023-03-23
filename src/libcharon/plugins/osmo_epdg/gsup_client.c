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

/* TODO: check license */

#include <collections/enumerator.h>
#include <collections/linked_list.h>
#include <collections/blocking_queue.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <threading/condvar.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include <library.h>

#include "ipa_client.h"
#include "gsup_client.h"
#include "osmo_epdg_utils.h"

typedef struct gsup_request_t gsup_request_t;
struct gsup_request_t {
	/**
	 * Mutex used to synchronize access to the condvar
	 */
	mutex_t *mutex;

	/**
	 * Condvar used to wait for a response
	 */
	condvar_t *condvar;

	struct msgb *msg;
	enum osmo_gsup_message_type msg_type;
	osmo_epdg_gsup_response_t *resp;
};

typedef struct private_osmo_epdg_gsup_client_t private_osmo_epdg_gsup_client_t;
struct private_osmo_epdg_gsup_client_t {
	/**
	 * Public osmo_epdg_gsup_client_t
	 */
	osmo_epdg_gsup_client_t public;

	osmo_epdg_ipa_client_t *ipa;

	/**
	 * List of all pending requests
	 */
	blocking_queue_t *pending;

	/**
	 * Current request which isn't part of linked list
	 */
	gsup_request_t *current_request;

	/**
	 * Mutex to protect current_request
	 */
	mutex_t *mutex;

	char *uri;

	stream_t *stream;
};

static gsup_request_t *gsup_request_create(enum osmo_gsup_message_type msg_type, struct msgb *msg)
{
	gsup_request_t *req = calloc(1, sizeof(gsup_request_t));
	if (!req)
	{
		return NULL;
	}

	req->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	req->condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	req->msg_type = msg_type;
	req->msg = msg;

	return req;
}

static void gsup_request_destroy(private_osmo_epdg_gsup_client_t *this, gsup_request_t *req)
{
	if (!req)
	{
		return;
	}

	if (req->mutex)
	{
		req->mutex->destroy(req->mutex);
	}

	if (req->condvar)
	{
		req->condvar->destroy(req->condvar);
	}

	if (req->msg)
	{
		free(req->msg);
	}

	if (req->resp)
	{
		free(req->resp);
	}
	free(req);
}

static struct msgb *encode_to_msgb(struct osmo_gsup_message *gsup_msg)
{
	chunk_t msg_chunk;
	struct msgb *msg;
	int ret;

	msg_chunk = chunk_alloc(4000);
	if (msg_chunk.ptr == NULL)
	{
		return NULL;
	}

	msg = chunk_to_msgb(&msg_chunk);
	if (!msg)
	{
		goto free_msg;
	}

	/* reserve headroom */
	msgb_reserve(msg, 64);
	ret = osmo_gsup_encode(msg, gsup_msg);
	if (ret)
	{
		DBG1(DBG_NET, "GSUP: couldn't encode gsup message %d.", ret);
		goto free_msg;
	}

	return msg;

free_msg:
	chunk_free(&msg_chunk);
	return NULL;
}

/**
 * enqueue a message/request to be send out and wait for the response.
 * 
 * when exiting enqueue, it must be guaranteed the req isn't referenced by anything
 * @param timeout_ms A timeout in ms
 * @return TRUE is the request timed out.
 */
static bool enqueue(private_osmo_epdg_gsup_client_t *this, gsup_request_t *req, u_int timeout_ms)
{
	bool ret = FALSE;

	DBG1(DBG_NET, "Enqueuing message. Waiting %d ms for an answer", timeout_ms);
	req->mutex->lock(req->mutex);
	this->pending->enqueue(this->pending, req);
	ret = req->condvar->timed_wait(req->condvar, req->mutex, timeout_ms);
	if (ret)
	{
		void *found = this->pending->remove(this->pending, req);
		if (!found)
		{
			this->mutex->lock(this->mutex);
			if (this->current_request == req)
			{
				this->current_request = NULL;
			}
			this->mutex->unlock(this->mutex);
		}
		DBG1(DBG_NET, "Message timedout!");
	}

	return ret;
}

METHOD(osmo_epdg_gsup_client_t, tunnel_request, osmo_epdg_gsup_response_t*,
        private_osmo_epdg_gsup_client_t *this, char *imsi, char *apn)
{
	struct osmo_gsup_message gsup_msg = {0};
	struct osmo_gsup_pdp_info *pdp;
	struct msgb *msg;
	bool timedout;

	DBG1(DBG_NET, "Tunnel Request Request for %s", imsi);
	gsup_msg.message_type = OSMO_GSUP_MSGT_EPDG_TUNNEL_REQUEST;
	gsup_msg.current_rat_type = OSMO_RAT_EUTRAN_SGS;
	if (!imsi || strlen(imsi) == 0)
	{
		/* TODO: inval imsi! */
		return NULL;
	}
	strncpy(gsup_msg.imsi, imsi, sizeof(gsup_msg.imsi));

	if (apn && strlen(apn) > 0)
	{
		gsup_msg.num_pdp_infos = 1;
		pdp = &gsup_msg.pdp_infos[0];
		pdp->context_id = 1;
		pdp->have_info = 1;
		pdp->apn_enc = apn;
		pdp->apn_enc_len = strlen(apn);
	}

	msg = encode_to_msgb(&gsup_msg);
	if (!msg)
	{
		DBG1(DBG_NET, "Couldn't alloc/encode gsup message.");
		return NULL;
	}

	gsup_request_t *req = gsup_request_create(OSMO_GSUP_MSGT_EPDG_TUNNEL_REQUEST, msg);
	osmo_epdg_gsup_response_t *resp = NULL;
	timedout = enqueue(this, req, 5000);
	if (timedout)
	{
		gsup_request_destroy(this, req);
		return NULL;
	}

	resp = req->resp;
	req->resp = NULL;
	gsup_request_destroy(this, req);
	return resp;
}

METHOD(osmo_epdg_gsup_client_t, send_auth_request, osmo_epdg_gsup_response_t*,
        private_osmo_epdg_gsup_client_t *this, char *imsi, uint8_t cn_domain, chunk_t *auts, chunk_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};
	struct msgb *msg;
	bool timedout;

	DBG1(DBG_NET, "Send Auth Request for %s", imsi);
	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	gsup_msg.num_auth_vectors = 1;
	gsup_msg.current_rat_type = OSMO_RAT_EUTRAN_SGS;

	if (!imsi || strlen(imsi) == 0)
	{
		/* TODO: inval imsi! */
		return NULL;
	}
	strncpy(gsup_msg.imsi, imsi, sizeof(gsup_msg.imsi));

	switch (cn_domain)
	{
		case 0:
			/* empty cn_domain */
			break;
		case OSMO_GSUP_CN_DOMAIN_PS:
		case OSMO_GSUP_CN_DOMAIN_CS:
			gsup_msg.cn_domain = cn_domain;
			break;
		default:
			DBG1(DBG_NET, "GSUP: SAIR: Ignoring invalid cn_domain message.");
			break;
	}

	if (auts && auts->ptr && auts->len != 0)
	{
		if (auts->len != 14)
		{
			/* TODO: inval auts */
			return NULL;
		}

		gsup_msg.auts = auts->ptr;
	}

	/* TODO check for other sizes */
	if (auts_rand && auts_rand->ptr && auts_rand->len != 0)
	{
		if (auts_rand->len != 16)
		{
			/* TODO: inval auts */
			return NULL;
		}

		gsup_msg.rand = auts_rand->ptr;
	}

	msg = encode_to_msgb(&gsup_msg);
	if (!msg)
	{
		DBG1(DBG_NET, "Couldn't alloc/encode gsup message.");
		return NULL;
	}

	gsup_request_t *req = gsup_request_create(OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST, msg);
	osmo_epdg_gsup_response_t *resp = NULL;
	timedout = enqueue(this, req, 5000);
	if (timedout)
	{
		gsup_request_destroy(this, req);
		return NULL;
	}

	resp = req->resp;
	req->resp = NULL;
	gsup_request_destroy(this, req);

	return resp;
}

METHOD(osmo_epdg_gsup_client_t, update_location, osmo_epdg_gsup_response_t *,
        private_osmo_epdg_gsup_client_t *this, char *imsi, uint8_t cn_domain)
{
	struct osmo_gsup_message gsup_msg = {0};
	struct msgb *msg;
	bool timedout;

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	gsup_msg.current_rat_type = OSMO_RAT_EUTRAN_SGS;

	if (!imsi || strlen(imsi) == 0)
	{
		DBG1(DBG_NET, "GSUP: ULR: Invalid IMSI!");
		return NULL;
	}
	strncpy(gsup_msg.imsi, imsi, sizeof(gsup_msg.imsi));

	switch (cn_domain)
	{
		case 0:
			/* empty cn_domain */
			break;
		case OSMO_GSUP_CN_DOMAIN_PS:
		case OSMO_GSUP_CN_DOMAIN_CS:
			gsup_msg.cn_domain = cn_domain;
			break;
		default:
			DBG1(DBG_NET, "GSUP: ULR: Ignoring invalid cn_domain message.");
			break;
	}

	msg = encode_to_msgb(&gsup_msg);
	if (!msg)
	{
		DBG1(DBG_NET, "GSUP: ULR: Couldn't alloc/encode gsup message.");
		return NULL;
	}

	gsup_request_t *req = gsup_request_create(OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST, msg);
	osmo_epdg_gsup_response_t *resp = NULL;
	timedout = enqueue(this, req, 5000);
	if (timedout)
	{
		gsup_request_destroy(this, req);
		return NULL;
	}

	resp = req->resp;
	req->resp = NULL;
	gsup_request_destroy(this, req);

	return resp;
}

METHOD(osmo_epdg_gsup_client_t, destroy, void,
        private_osmo_epdg_gsup_client_t *this)
{
	free(this->uri);
	free(this);
}

void tx_insert_data_result(private_osmo_epdg_gsup_client_t *this, char *imsi, uint8_t cn_domain)
{
	struct osmo_gsup_message gsup_msg = {0};
	struct msgb *msg;

	gsup_msg.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	if (!imsi || strlen(imsi) == 0)
	{
		DBG1(DBG_NET, "GSUP: ULR: Invalid IMSI!");
	}
	strncpy(gsup_msg.imsi, imsi, sizeof(gsup_msg.imsi));

	switch (cn_domain)
	{
		case 0:
			/* empty cn_domain */
			break;
		case OSMO_GSUP_CN_DOMAIN_PS:
		case OSMO_GSUP_CN_DOMAIN_CS:
			gsup_msg.cn_domain = cn_domain;
			break;
		default:
			DBG1(DBG_NET, "GSUP: ULR: Ignoring invalid cn_domain message.");
			break;
	}

	msg = encode_to_msgb(&gsup_msg);
	if (!msg)
	{
		DBG1(DBG_NET, "GSUP: ULR: Couldn't alloc/encode gsup message.");
	}
	this->ipa->send(this->ipa, IPAC_PROTO_EXT_GSUP, msg);
}

static void signal_request(gsup_request_t *req, osmo_epdg_gsup_response_t *resp)
{
	req->mutex->lock(req->mutex);
	req->resp = resp;
	req->condvar->signal(req->condvar);
	req->mutex->unlock(req->mutex);
}

static bool on_recv_pdu(void *data, osmo_epdg_ipa_client_t *client, struct msgb *pdu)
{
	private_osmo_epdg_gsup_client_t *this = data;
	osmo_epdg_gsup_response_t *resp;
	int ret;

	resp = calloc(1, sizeof(*resp));
	if (!resp)
	{
		return TRUE;
	}

	ret = osmo_gsup_decode(msgb_l2(pdu), msgb_l2len(pdu), &resp->gsup);
	if (ret) {
		// TODO: failed to decode response. Close connection
		goto out;
	}

	switch (resp->gsup.message_type)
	{
		case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
			tx_insert_data_result(this, resp->gsup.imsi, resp->gsup.cn_domain);
			goto out;
		case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		case OSMO_GSUP_MSGT_EPDG_TUNNEL_ERROR:
		case OSMO_GSUP_MSGT_EPDG_TUNNEL_RESULT:
			this->mutex->lock(this->mutex);
			if ((this->current_request->msg_type & 0xfffffffc) != (resp->gsup.message_type & 0xfffffffc))
			{
				/* Request, Result, Error, Other are encoded in the last 2 bits */
				DBG1(DBG_NET, "GSUP: received non matching Result. Requested %s but received %s",
					osmo_gsup_message_type_name(this->current_request->msg_type),
					osmo_gsup_message_type_name(resp->gsup.message_type));
				goto out;
			}
			if (!this->current_request)
			{
				DBG2(DBG_NET, "GSUP: received response when no request waiting %02x. This might came too late.", resp->gsup.message_type);
				this->mutex->unlock(this->mutex);
				goto out;
			}
			signal_request(this->current_request, resp);
			this->current_request = NULL;
			this->mutex->unlock(this->mutex);
			break;
		default:
			DBG1(DBG_NET, "GSUP received unknown message type %02x", resp->gsup.message_type);
			goto out;
	}
	free(pdu);
	return TRUE;

out:
	free(resp);
	free(pdu);
	return TRUE;
}

static int disconnect_gsup(private_osmo_epdg_gsup_client_t *this)
{
	this->ipa->disconnect(this->ipa);
	return 0;
}

/* TODO: worker thread which sends out enqueue'd message ! */
static job_requeue_t queue_worker(private_osmo_epdg_gsup_client_t *this)
{
	int ret;
	gsup_request_t *req;
	this->mutex->lock(this->mutex);
	if (this->current_request)
	{
		/* TODO: should we join the signal? */
		this->mutex->unlock(this->mutex);
		return JOB_REQUEUE_FAIR;
	}
	this->mutex->unlock(this->mutex);

	/* TODO: replace pending with a thread safe queue, but non-blocking */
	req = this->pending->dequeue(this->pending);

	this->mutex->lock(this->mutex);
	if (this->current_request)
	{
		/* TODO: how could this happen? */
		this->mutex->unlock(this->mutex);
		signal_request(req, NULL);
		return JOB_REQUEUE_FAIR;
	}
	this->current_request = req;
	this->mutex->unlock(this->mutex);

	ret = this->ipa->send(this->ipa, IPAC_PROTO_EXT_GSUP, req->msg);
	req->msg = NULL;
	if (ret < 0)
	{
		/* TODO: disconnect & reconnect, but request is lost for now */
		/* TODO: wake up request */
		signal_request(req, NULL);
	}
	return JOB_REQUEUE_FAIR;
}

osmo_epdg_gsup_client_t *osmo_epdg_gsup_client_create(char *uri)
{
	private_osmo_epdg_gsup_client_t *this;
	DBG1(DBG_NET, "Starting osmo-epdg");

	INIT(this,
			.public = {
				.send_auth_request = _send_auth_request,
				.update_location = _update_location,
				.tunnel_request = _tunnel_request,
				.destroy = _destroy,
			},
			.uri = strdup(uri),
			.pending = blocking_queue_create(),
			.current_request = NULL,
			.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
			.ipa = osmo_epdg_ipa_client_create(uri),
		);
	this->ipa->on_recv(this->ipa, IPAC_PROTO_EXT_GSUP, on_recv_pdu, this);
	/* I would more like to have either an internal event which unblocks the queue. */
	/* src/libipsec/ipsec_event_relay.c */
        lib->processor->queue_job(lib->processor,
                (job_t*)callback_job_create_with_prio((callback_job_cb_t)queue_worker,
                        this, NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	return &this->public;
}
