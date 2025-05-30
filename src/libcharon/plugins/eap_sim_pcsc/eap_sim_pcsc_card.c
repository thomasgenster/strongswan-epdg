/*
 * Copyright (C) 2011 Duncan Salerno
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

#include "eap_sim_pcsc_card.h"

#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include <daemon.h>

typedef struct private_eap_sim_pcsc_card_t private_eap_sim_pcsc_card_t;

/**
 * Private data of an eap_sim_pcsc_card_t object.
 */
struct private_eap_sim_pcsc_card_t {

	/**
	 * Public eap_sim_pcsc_card_t interface.
	 */
	eap_sim_pcsc_card_t public;

	char auts[AKA_AUTS_LEN];
};

/**
 * Maximum length for an IMSI.
 */
#define SIM_IMSI_MAX_LEN 15

/**
 * Length of the status at the end of response APDUs.
 */
#define APDU_STATUS_LEN 2

/**
 * First byte of status word indicating success.
 */
#define APDU_SW1_SUCCESS 0x90

/**
 * First byte of status word indicating there is response data to be read.
 */
#define APDU_SW1_RESPONSE_DATA 0x9f

/**
 * Decode IMSI EF (Elementary File) into an ASCII string
 */
static bool decode_imsi_ef(unsigned char *input, int input_len, char *output)
{
	/* Only digits 0-9 valid in IMSIs */
	static const char bcd_num_digits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', '\0', '\0', '\0', '\0', '\0', '\0'
	};
	int i;

	/* Check length byte matches how many bytes we have, and that input
	 * is correct length for an IMSI */
	if (input[0] != input_len-1 || input_len < 2 || input_len > 9)
	{
		return FALSE;
	}

	/* Check type byte is IMSI (bottom 3 bits == 001) */
	if ((input[1] & 0x07) != 0x01)
	{
		return FALSE;
	}
	*output++ = bcd_num_digits[input[1] >> 4];

	for (i = 2; i < input_len; i++)
	{
		*output++ = bcd_num_digits[input[i] & 0xf];
		*output++ = bcd_num_digits[input[i] >> 4];
	}

	*output++ = '\0';
	return TRUE;
}

METHOD(simaka_card_t, get_triplet, bool,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN])
{
	status_t found = FALSE;
	LONG rv;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	LPSTR mszReaders;
	char *cur_reader;
	char full_nai[128];
	SCARDHANDLE hCard;
	enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;

	snprintf(full_nai, sizeof(full_nai), "%Y", id);

	DBG2(DBG_IKE, "looking for triplet: %Y rand %b", id, rand, SIM_RAND_LEN);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
		return FALSE;
	}

	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders120: %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	mszReaders = malloc(sizeof(char)*dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders128: %s", pcsc_stringify_error(rv));
		free(mszReaders);
		return FALSE;
	}

	/* mszReaders is a multi-string of readers, separated by '\0' and
	 * terminated by an additional '\0' */
	for (cur_reader = mszReaders; *cur_reader != '\0' && found == FALSE;
		 cur_reader += strlen(cur_reader) + 1)
	{
		DWORD dwActiveProtocol = -1;
		const SCARD_IO_REQUEST *pioSendPci;
		SCARD_IO_REQUEST pioRecvPci;
		BYTE pbRecvBuffer[64];
		DWORD dwRecvLength;
		char imsi[SIM_IMSI_MAX_LEN + 1];

		/* See GSM 11.11 for SIM APDUs */
		static const BYTE pbSelectMF[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x3f, 0x00 };
		static const BYTE pbSelectDFGSM[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x7f, 0x20 };
		static const BYTE pbSelectIMSI[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x6f, 0x07 };
		static const BYTE pbReadBinary[] = { 0xa0, 0xb0, 0x00, 0x00, 0x09 };
		BYTE pbRunGSMAlgorithm[5 + SIM_RAND_LEN] = { 0xa0, 0x88, 0x00, 0x00, 0x10 };
		static const BYTE pbGetResponse[] = { 0xa0, 0xc0, 0x00, 0x00, 0x0c };

		/* If on 2nd or later reader, make sure we end the transaction
		 * and disconnect card in the previous reader */
		switch (hCard_status)
		{
			case TRANSACTION:
				SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case CONNECTED:
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case DISCONNECTED:
				hCard_status = DISCONNECTED;
		}

		/* Copy RAND into APDU */
		memcpy(pbRunGSMAlgorithm + 5, rand, SIM_RAND_LEN);

		rv = SCardConnect(hContext, cur_reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardConnect: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = CONNECTED;

		switch(dwActiveProtocol)
		{
			case SCARD_PROTOCOL_T0:
				pioSendPci = SCARD_PCI_T0;
				break;
			case SCARD_PROTOCOL_T1:
				pioSendPci = SCARD_PCI_T1;
				break;
			default:
				DBG1(DBG_IKE, "Unknown SCARD_PROTOCOL");
				continue;
		}

		/* Start transaction */
		rv = SCardBeginTransaction(hCard);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardBeginTransaction: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = TRANSACTION;

		/* APDU: Select MF */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectMF, sizeof(pbSelectMF),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select MF failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Select DF GSM */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectDFGSM, sizeof(pbSelectDFGSM),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select DF GSM failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Select IMSI */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectIMSI, sizeof(pbSelectIMSI),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Read Binary (of IMSI) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbReadBinary, sizeof(pbReadBinary),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		if (!decode_imsi_ef(pbRecvBuffer, dwRecvLength-APDU_STATUS_LEN, imsi))
		{
			DBG1(DBG_IKE, "Couldn't decode IMSI EF: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* The IMSI could be post/prefixed in the full NAI, so just make sure
		 * it's in there */
		if (!(strlen(full_nai) && strstr(full_nai, imsi)))
		{
			DBG1(DBG_IKE, "Not the SIM we're looking for, IMSI: %s", imsi);
			continue;
		}

		/* APDU: Run GSM Algorithm */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci,
						   pbRunGSMAlgorithm, sizeof(pbRunGSMAlgorithm),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Run GSM Algorithm failed: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Get Response (of Run GSM Algorithm) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbGetResponse, sizeof(pbGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}

		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Get Response failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* Extract out Kc and SRES from response */
		if (dwRecvLength == SIM_SRES_LEN + SIM_KC_LEN + APDU_STATUS_LEN)
		{
			memcpy(sres, pbRecvBuffer, SIM_SRES_LEN);
			memcpy(kc, pbRecvBuffer+4, SIM_KC_LEN);
			/* This will also cause the loop to exit */
			found = TRUE;
		}
		else
		{
			DBG1(DBG_IKE, "Get Response incorrect length: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Transaction will be ended and card disconnected at the
		 * beginning of this loop or after this loop */
	}

	/* Make sure we end any previous transaction and disconnect card */
	switch (hCard_status)
	{
		case TRANSACTION:
			SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case CONNECTED:
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case DISCONNECTED:
			hCard_status = DISCONNECTED;
	}

	rv = SCardReleaseContext(hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardReleaseContext: %s", pcsc_stringify_error(rv));
	}

	free(mszReaders);
	return found;
}

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	status_t found = FAILED;
	LONG rv;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	LPSTR mszReaders;
	char *cur_reader;
	char full_nai[128];
	SCARDHANDLE hCard;
	enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;

	snprintf(full_nai, sizeof(full_nai), "%Y", id);

	DBG2(DBG_IKE, "looking for quintuplet: %Y\nrand %b\nautn %b", id, rand, AKA_RAND_LEN, autn, AKA_AUTN_LEN);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
		return FAILED;
	}

	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders391 he: %s", pcsc_stringify_error(rv));
		return FAILED;
	}
	mszReaders = malloc(sizeof(char)*dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders399: %s", pcsc_stringify_error(rv));
		free(mszReaders);
		return FAILED;
	}

	/* mszReaders is a multi-string of readers, separated by '\0' and
	 * terminated by an additional '\0' */
	for (cur_reader = mszReaders; *cur_reader != '\0' && found == FAILED;
		 cur_reader += strlen(cur_reader) + 1)
	{
		DWORD dwActiveProtocol = -1;
		const SCARD_IO_REQUEST *pioSendPci;
		SCARD_IO_REQUEST pioRecvPci;
		BYTE pbRecvBuffer[128];
		DWORD dwRecvLength;
		int aid_length;

		/* See GSM 11.11 for SIM APDUs */
		static const BYTE pbSelectEFDIR[] = { 0x00, 0xa4, 0x00, 0x04, 0x02, 0x2f, 0x00, 0x00 };
		static const BYTE pbSelectAID_prefix[] = { 0x00, 0xa4, 0x04, 0x04 };
		static BYTE pbReadAID[4+1] = { 0x00, 0xb2, 0x01, 0x04 };
		static BYTE pbAuthenticate[6+AKA_RAND_LEN+1+AKA_AUTN_LEN] = { 0x00, 0x88, 0x00, 0x81, 0x22, 0x10 };
		static BYTE pbGetResponse[4+1] = { 0x00, 0xc0, 0x00, 0x00 };

		/* If on 2nd or later reader, make sure we end the transaction
		 * and disconnect card in the previous reader */
		switch (hCard_status)
		{
			case TRANSACTION:
				SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case CONNECTED:
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case DISCONNECTED:
				hCard_status = DISCONNECTED;
		}

		rv = SCardConnect(hContext, cur_reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardConnect: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = CONNECTED;

		switch(dwActiveProtocol)
		{
			case SCARD_PROTOCOL_T0:
				pioSendPci = SCARD_PCI_T0;
				break;
			case SCARD_PROTOCOL_T1:
				pioSendPci = SCARD_PCI_T1;
				break;
			default:
				DBG1(DBG_IKE, "Unknown SCARD_PROTOCOL");
				continue;
		}

		/* Start transaction */
		rv = SCardBeginTransaction(hCard);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardBeginTransaction: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = TRANSACTION;

		/* APDU: Select EF.DIR */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectEFDIR, sizeof(pbSelectEFDIR),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != 97)
		{
			DBG1(DBG_IKE, "Select EF.DIR failed:\nsent %b\nreceived %b", pbSelectEFDIR, sizeof(pbSelectEFDIR),
			     pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Copy SW2 to GetResponse */
		pbGetResponse[4] = pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN+1];

		/* APDU: Get Response (of Select EF.DIR) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbGetResponse, sizeof(pbGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}

		if (dwRecvLength < 1 + APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Get Response failed:\nsent %b\nreceived %b", pbGetResponse,
			     sizeof(pbGetResponse), pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Copy record lenth */
		pbReadAID[4] = pbRecvBuffer[7];

		/* APDU: Read first AID */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbReadAID, sizeof(pbReadAID),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Read of AID failed:\nsent %b\nreceived %b", pbReadAID, sizeof(pbReadAID),
			     pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Copy AID */
		aid_length = pbRecvBuffer[3];
		BYTE pbSelectAID[4+1+aid_length];
		memcpy(pbSelectAID, pbSelectAID_prefix, 4);
		pbSelectAID[4] = aid_length;
		memcpy(pbSelectAID+4+1, pbRecvBuffer+4, aid_length);

		/* APDU: Select AID */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectAID, sizeof(pbSelectAID),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != 97)
		{
			DBG1(DBG_IKE, "Select ADF.USIM failed:\nsent %b\nreceived %b", pbSelectAID, sizeof(pbSelectAID),
			     pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Copy RAND + AUTN into APDU */
		memcpy(pbAuthenticate + 6, rand, AKA_RAND_LEN);
		pbAuthenticate[6 + AKA_RAND_LEN] = 0x10;
		memcpy(pbAuthenticate + 6 + AKA_RAND_LEN + 1, autn, AKA_AUTN_LEN);

		/* APDU: Authenticate */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci,
						   pbAuthenticate, sizeof(pbAuthenticate),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != 97)
		{
			DBG1(DBG_IKE, "Authenticate failed:\nsent %b\nreceived %b", pbAuthenticate,
			     sizeof(pbAuthenticate), pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Copy SW2 to GetResponse */
		pbGetResponse[4] = pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN+1];

		/* APDU: Get Response (of Authenticate) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbGetResponse, sizeof(pbGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}

		if (dwRecvLength < 1 + APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Get Response failed:\nsent %b\nreceived %b", pbGetResponse,
			     sizeof(pbGetResponse), pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Extract out AUTS and store it */
		if (pbRecvBuffer[0] == 0xdc)
		{
			if (dwRecvLength < 2 + AKA_AUTS_LEN + APDU_STATUS_LEN) {
				DBG1(DBG_IKE, "Get Response too short:\n%b", pbRecvBuffer, (u_int)dwRecvLength);
				continue;
			}
			memcpy(this->auts, pbRecvBuffer + 2, AKA_AUTS_LEN);
			DBG1(DBG_IKE, "Sync failure, storing AUTS %b", this->auts, AKA_AUTS_LEN);
			/* This result code will trigger resync() function */
			found = INVALID_STATE;
			continue;
		}

		/* Extract out RES/CK/IK from response */
		if (pbRecvBuffer[0] == 0xdb)
		{
			*res_len = pbRecvBuffer[1];
			if (dwRecvLength < 2 + *res_len + 1 + AKA_CK_LEN + 1 + AKA_IK_LEN + APDU_STATUS_LEN) {
				DBG1(DBG_IKE, "Get Response too short:\n%b", pbRecvBuffer, (u_int)dwRecvLength);
				continue;
			}
			memcpy(res, pbRecvBuffer + 2, *res_len);
			memcpy(ck, pbRecvBuffer + 2 + *res_len + 1, AKA_CK_LEN);
			memcpy(ik, pbRecvBuffer + 2 + *res_len + 1 + AKA_CK_LEN + 1, AKA_IK_LEN);
			DBG1(DBG_IKE, "Authentication success:\nRES %b\ncK %b\niK %b", res, *res_len, ck,
			     AKA_CK_LEN, ik, AKA_IK_LEN);
			found = SUCCESS;
			continue;
		}
		else
		{
			DBG1(DBG_IKE, "Get Response unknown:\n%b", pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Transaction will be ended and card disconnected at the
		 * beginning of this loop or after this loop */
	}

	/* Make sure we end any previous transaction and disconnect card */
	switch (hCard_status)
	{
		case TRANSACTION:
			SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case CONNECTED:
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case DISCONNECTED:
			hCard_status = DISCONNECTED;
	}

	rv = SCardReleaseContext(hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardReleaseContext: %s", pcsc_stringify_error(rv));
	}

	free(mszReaders);
	return found;
}

METHOD(simaka_card_t, resync, bool,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	/* AUTS */
	memcpy(auts, this->auts, AKA_AUTS_LEN);
	DBG3(DBG_IKE, "using AUTS:\n%b", auts, AKA_AUTS_LEN);

	return TRUE;
}


METHOD(eap_sim_pcsc_card_t, destroy, void,
	private_eap_sim_pcsc_card_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_sim_pcsc_card_t *eap_sim_pcsc_card_create()
{
	private_eap_sim_pcsc_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = _get_triplet,
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
