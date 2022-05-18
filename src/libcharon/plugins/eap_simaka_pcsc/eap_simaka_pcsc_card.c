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

#define _GNU_SOURCE
#include "eap_simaka_pcsc_card.h"
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include <daemon.h>
#include <string.h>

typedef struct private_eap_simaka_pcsc_card_t private_eap_simaka_pcsc_card_t;

/**
 * Private data of an eap_simaka_pcsc_card_t object.
 */
struct private_eap_simaka_pcsc_card_t {

	/**
	 * Public eap_simaka_pcsc_card_t interface.
	 */
	eap_simaka_pcsc_card_t public;
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

/*
 * Communication status
 */
#define ERROR_NONE 0
#define ERROR_SCARD 1
#define ERROR_CARD_ERROR 2

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
	private_eap_simaka_pcsc_card_t *this, identification_t *id,
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
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	mszReaders = malloc(sizeof(char)*dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
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
	private_eap_simaka_pcsc_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	status_t found = SUCCESS;
	LONG rv;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	LPSTR mszReaders;
	char *cur_reader;
	char full_nai[128];
	SCARDHANDLE hCard;
	enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;

	snprintf(full_nai, sizeof(full_nai), "%Y", id);

	DBG2(DBG_IKE, "looking for quintuplet: %Y rand %b", id, rand, SIM_RAND_LEN);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
		return FALSE;
	}

	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	mszReaders = malloc(sizeof(char)*dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
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
		BYTE pbRecvBuffer[512];
		DWORD dwRecvLength;
		char imsi[SIM_IMSI_MAX_LEN + 1];
        char aid_pattern[] = {0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}; //based on mitshell/card USIM.py:SELECT_ADF_USIM()
        char *correct_aid = NULL;
        int resLen = 0;

		/* USIM APDUs */
        BYTE abSelectEFDIR[] = {0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0x00};
        // CLA  SELECT  P1     P2    len
        // 0x00  0xC0  0x00   0x00  0x00
        BYTE abGetResponse[] = {0x00, 0xC0, 0x00, 0x00, 0x1C};
        // CLA  SELECT  P1 (by fileID) P2(UICC)  len  DATA (EF_IMSI address)
        // 0x00  0xA4    0x00          0x04      0x02 0x6F  0x07
        BYTE abSelectIMSI[] = {0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07};
        BYTE abReadRecord[] = {0x00, 0xB2, 0x01, 0x04, 0x00}; //Le byte (last one) set to 0x00 so complete record is read up to 256 bytes
        // CLA  SELECT  P1 (AID) P2(UICC)  len  DATA (AID)
        // 0x00  0xA4    0x04     0x04    '0xc', '0xa0', '0x0', '0x0', '0x0', '0x87', '0x10', '0x2', '0xff', '0x49', '0xff', '0x5', '0x89'
        BYTE abSelectUICC[] = {0x00, 0xA4, 0x04, 0x04};
        BYTE abReadBinary[] = {0x00, 0xB0, 0x00, 0x00, 0x09};
	    BYTE abAuthenticate[5 + 1 + SIM_RAND_LEN + 1 + SIM_RAND_LEN] = { 0x00, 0x88, 0x00, 0x81, 0x22, 0x10 }; //TOTAL_LEN + LEN(RAND) + RAND + LEN(AUTN) + AUTN
	    int i,j;
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
		memcpy(abAuthenticate + 6, rand, SIM_RAND_LEN);
		abAuthenticate[6 + SIM_RAND_LEN] = 0x10; //LEN of AUTN
		memcpy(abAuthenticate + 6 + SIM_RAND_LEN + 1, autn, SIM_RAND_LEN); //Copy AUTN into APDU

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

		/* APDU: Select EFDIR */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, abSelectEFDIR, sizeof(abSelectEFDIR),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);


        if (pbRecvBuffer[0] == 0x61 && dwRecvLength < 3)
	    {  // Response bytes available, GET RESPONSE needs to be run
           abGetResponse[4] = pbRecvBuffer[1]; //setting the expected length to the one sent by the card
           dwRecvLength = sizeof(pbRecvBuffer);
           rv = SCardTransmit(hCard, pioSendPci, abGetResponse, sizeof(abGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
 
        }
        else if ((pbRecvBuffer[0] == 0x6C && dwRecvLength < 3) || (pbRecvBuffer[0] == 0x67 && dwRecvLength < 3)) //WRONG length used, correcting it
	    {
            abSelectEFDIR[4] = pbRecvBuffer[1]; //setting the expected length to the one sent by the card
            dwRecvLength = sizeof(pbRecvBuffer);
            rv = SCardTransmit(hCard, pioSendPci, abSelectEFDIR, sizeof(abSelectEFDIR),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
	    }

		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
/*
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select EFDIR failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}*/

		for(j=0; j<5; j++) //Fingers crossed there is no SIM card with more than 5 applications in its EF_DIR
        {
  		  /* APDU: Read Record */
		  dwRecvLength = sizeof(pbRecvBuffer);
          abReadRecord[2] = j;
		  rv = SCardTransmit(hCard, pioSendPci, abReadRecord, sizeof(abReadRecord),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		  if (rv != SCARD_S_SUCCESS)
		  {
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		  }
/*
		  if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		  {
			DBG1(DBG_IKE, "Read Record failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		  }
*/
           DBG1(DBG_IKE, "READ RECORD #%d: %b", j, pbRecvBuffer,
				 (u_int)dwRecvLength);
           if ((pbRecvBuffer[0] == 0x6C && dwRecvLength < 3) || (pbRecvBuffer[0] == 0x67 && dwRecvLength < 3)) //WRONG length used, correcting it
	       {
             abReadRecord[4] = pbRecvBuffer[1]; //setting the expected length to the one sent by the card
             dwRecvLength = sizeof(pbRecvBuffer);
             rv = SCardTransmit(hCard, pioSendPci, abReadRecord, sizeof(abReadRecord),
					   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
	       }

		   if (rv != SCARD_S_SUCCESS)
		   {
			 DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			 continue;
		   }

		   if ((pbRecvBuffer[0]== 0x61) && (pbRecvBuffer[2] == 0x4F) && dwRecvLength > 6)
		   {
             correct_aid = memmem(pbRecvBuffer, dwRecvLength, aid_pattern, sizeof(aid_pattern));
             DBG1(DBG_IKE, "Detecting AIDs...");
             if(correct_aid)
               break;
           } else {
			DBG1(DBG_IKE, "Failed to get AID, will not be able to proceed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		   }
		 }

         if(!correct_aid)
         {
 		   DBG1(DBG_IKE, "NOT finding USIM AID (see ETSI TS 101 220 Annex E) pattern, will not be able to proceed: %b", pbRecvBuffer,
			 (u_int)dwRecvLength);
			continue;

          } else {
            unsigned char aid[pbRecvBuffer[3]]; //the transaction buffer contains the right AID with its length
	        for(i=0; i < sizeof(aid); i++) {
              aid[i] = (*correct_aid);
              correct_aid++;
            }
            unsigned char final_apdu[sizeof(aid)+4];
            for (i=0; i < sizeof(abSelectUICC); i++) {
              final_apdu[i] = abSelectUICC[i];
            }
            final_apdu[sizeof(abSelectUICC)] = sizeof(aid); //len byte
            for (i=0; i < sizeof(aid); i++) { //adding AID to the APDU
              final_apdu[i+5] = aid[i];
            }
            DBG1(DBG_IKE, "Got AID: %b", aid,
		              sizeof(aid));

           DBG1(DBG_IKE, "Selecting UICC...");
	  	   /* APDU: Select UICC */
		   dwRecvLength = sizeof(pbRecvBuffer);
           DBG1(DBG_IKE, "Sending APDU: %b", final_apdu,
		                (u_int)pbRecvBuffer[3]+5);

		   rv = SCardTransmit(hCard, pioSendPci, final_apdu, pbRecvBuffer[3]+5,
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
           if (rv != SCARD_S_SUCCESS)
           {
             DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
             continue;
           }
           if (pbRecvBuffer[0] == 0x61 && dwRecvLength < 3)
           {  // Response bytes available, GET RESPONSE needs to be run
             abGetResponse[4] = pbRecvBuffer[1]; //setting the expected length to the one sent by the card
             dwRecvLength = sizeof(pbRecvBuffer);
             rv = SCardTransmit(hCard, pioSendPci, abGetResponse, sizeof(abGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
           }
         }

/*       if (dwRecvLength < APDU_STATUS_LEN ||
                       pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		 {
			DBG1(DBG_IKE, "Select UICC failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		 }
*/


        DBG1(DBG_IKE, "Selecting IMSI...");
		/* APDU: Select IMSI */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, abSelectIMSI, sizeof(abSelectIMSI),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
        if (pbRecvBuffer[0] == 0x61 && dwRecvLength < 3)
        {  // Response bytes available, GET RESPONSE needs to be run
          abGetResponse[4] = pbRecvBuffer[1]; //setting the expected length to the one sent by the card
          dwRecvLength = sizeof(pbRecvBuffer);
          rv = SCardTransmit(hCard, pioSendPci, abGetResponse, sizeof(abGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
        }
/*		
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}
 */
		/* APDU: Read Binary (of IMSI) */
        DBG1(DBG_IKE, "Reading binary of IMSI...");
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, abReadBinary, sizeof(abReadBinary),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		DBG1(DBG_IKE, "Response: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);

		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Read binary of IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		if (!decode_imsi_ef(pbRecvBuffer, dwRecvLength-APDU_STATUS_LEN, imsi))
		{
			DBG1(DBG_IKE, "Couldn't decode IMSI EF: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}
		DBG1(DBG_IKE, "Got IMSI: %s", imsi);
		/* The IMSI could be post/prefixed in the full NAI, so just make sure
		 * it's in there */
		if (!(strlen(full_nai) && strstr(full_nai, imsi)))
		{
			DBG1(DBG_IKE, "Not the SIM we're looking for, IMSI: %s", imsi);
			continue;
		}

		/* APDU: Authenticate */
                DBG1(DBG_IKE, "Running AUTHENTICATE...");
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci,
						   abAuthenticate, sizeof(abAuthenticate),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}

                if (pbRecvBuffer[0] == 0x61 && dwRecvLength < 3)
	        {  // Response bytes available, GET RESPONSE needs to be run
                   abGetResponse[4] = pbRecvBuffer[1]; //setting the expected length to the one sent by the card
                   dwRecvLength = sizeof(pbRecvBuffer);
                   rv = SCardTransmit(hCard, pioSendPci, abGetResponse, sizeof(abGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
 
                }

		DBG1(DBG_IKE, "Response: %b",
			 pbRecvBuffer, (u_int)dwRecvLength);

/*		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Authenticate failed: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}
*/
        /* Parsing data from the response into RES, CK, IK */
		if(pbRecvBuffer[0] == 0xDB)
		{
                        DBG1(DBG_IKE, "Successful 3G authentication");
			if(pbRecvBuffer[1] == 0x08 || pbRecvBuffer[1] == 0x04) //RES
			{
                                resLen = pbRecvBuffer[1];
				for(i=0; i< pbRecvBuffer[1]; i++)
				{
					res[i] = pbRecvBuffer[i+2];
				}
                                (*res_len) = resLen;
			} else {
				DBG1(DBG_IKE, "RES not 8 or 4 byte long, can't copy it.\n");
				continue;
			}
			if(pbRecvBuffer[resLen+2] == 0x10) //CK SUCCESS_BYTE 0xDB(len=1) + RES_LEN(len1) + resLen
			{
				for(i=0; i<16; i++)
				{
					ck[i] = pbRecvBuffer[i+resLen+3];
				}
			} else {
				DBG1(DBG_IKE, "CK not 16 byte long, can't copy it\n");
				continue;
			}
			if(pbRecvBuffer[resLen+3+16] == 0x10) //IK SUCCESS_BYTE(len1) + RES_LEN(len1) + res + CK_LEN(len1) + CK(len16)
			{
				for(i=0; i<16; i++)
				{
					ik[i] = pbRecvBuffer[i+ resLen+3+16+1];
				}
			} else {
				DBG1(DBG_IKE, "IK not 16 byte long, can't copy it\n");
				continue;
			}
                        DBG1(DBG_IKE, "KEYs established. RES: %b", res, resLen);
                        DBG1(DBG_IKE, "KEYs established. CK: %b", ck, 16);
                        DBG1(DBG_IKE, "KEYs established. IK: %b", ik, 16);
			found = SUCCESS;

		}
		if(pbRecvBuffer[0] == 0xDC)
		{
			DBG1(DBG_IKE, "Sync error between SIM card and network, currently NOT supported.\n");
                        return NOT_SUPPORTED;
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

METHOD(eap_simaka_pcsc_card_t, destroy, void,
	private_eap_simaka_pcsc_card_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_simaka_pcsc_card_t *eap_simaka_pcsc_card_create()
{
	private_eap_simaka_pcsc_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = _get_triplet,
				.get_quintuplet = _get_quintuplet,
				.resync = (void*)return_false,
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

