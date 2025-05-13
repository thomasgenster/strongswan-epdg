/*
 * Copyright (C) 2025 Your Name
 */

 #include "eap_sim_http_card.h"

 #include <curl/curl.h>
 #include <string.h>
 #include <daemon.h>

 typedef struct private_eap_sim_http_card_t private_eap_sim_http_card_t;

 struct private_eap_sim_http_card_t {
	 eap_sim_http_card_t public;
	 char auts[AKA_AUTS_LEN];
 };

 struct MemoryStruct {
	 char *memory;
	 size_t size;
 };

 static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
 {
	 // ... same as before ...
 }

 /**
  * Simple hex string to bytes converter
  */
 static bool hex2bytes(char *hex, u_int8_t *bytes, size_t len)
 {
	 size_t hex_len = strlen(hex);
	 if (hex_len != len * 2)
	 {
		 return FALSE;
	 }

	 for (size_t i = 0; i < len; i++)
	 {
		 if (sscanf(hex + (i * 2), "%2hhx", &bytes[i]) != 1)
		 {
			 return FALSE;
		 }
	 }
	 return TRUE;
 }

 /**
  * Simple JSON value extractor
  */
 static bool get_json_value(const char *json, const char *key, char *value, size_t value_len)
 {
	 char search[128];
	 char *start, *end;

	 snprintf(search, sizeof(search), "\"%s\":\"", key);
	 start = strstr(json, search);
	 if (!start)
	 {
		 return FALSE;
	 }

	 start += strlen(search);
	 end = strchr(start, '"');
	 if (!end || (end - start) >= value_len)
	 {
		 return FALSE;
	 }

	 memcpy(value, start, end - start);
	 value[end - start] = '\0';
	 return TRUE;
 }

 static bool http_get_auth_data(char *rand, char *autn, char *res, char *ck, char *ik, int *res_len)
 {
	 CURL *curl;
	 CURLcode curl_rc;
	 struct MemoryStruct chunk = {.memory = malloc(1), .size = 0};
	 char url[512];
	 bool success = FALSE;
	 char hex_res[64], hex_ck[64], hex_ik[64];

	 curl = curl_easy_init();
	 if (!curl)
	 {
		 DBG1(DBG_IKE, "failed to initialize CURL");
		 free(chunk.memory);
		 return FALSE;
	 }

	 snprintf(url, sizeof(url), "http://localhost/auth?rand=%02x%02x%02x%02x&autn=%02x%02x%02x%02x",
			  rand[0], rand[1], rand[2], rand[3],
			  autn[0], autn[1], autn[2], autn[3]);

	 curl_easy_setopt(curl, CURLOPT_URL, url);
	 curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	 curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	 curl_rc = curl_easy_perform(curl);
	 if (curl_rc != CURLE_OK)
	 {
		 DBG1(DBG_IKE, "curl_easy_perform() failed: %s", curl_easy_strerror(curl_rc));
		 goto cleanup;
	 }

	 // Parse JSON response manually
	 if (!get_json_value(chunk.memory, "res", hex_res, sizeof(hex_res)) ||
		 !get_json_value(chunk.memory, "ck", hex_ck, sizeof(hex_ck)) ||
		 !get_json_value(chunk.memory, "ik", hex_ik, sizeof(hex_ik)))
	 {
		 DBG1(DBG_IKE, "failed to parse JSON response");
		 goto cleanup;
	 }

	 // Convert hex strings to bytes
	 *res_len = strlen(hex_res) / 2;
	 if (!hex2bytes(hex_res, res, *res_len) ||
		 !hex2bytes(hex_ck, ck, AKA_CK_LEN) ||
		 !hex2bytes(hex_ik, ik, AKA_IK_LEN))
	 {
		 DBG1(DBG_IKE, "failed to convert hex strings");
		 goto cleanup;
	 }

	 success = TRUE;

 cleanup:
	 curl_easy_cleanup(curl);
	 free(chunk.memory);
	 return success;
 }

METHOD(simaka_card_t, get_quintuplet, status_t,
    private_eap_sim_http_card_t *this, identification_t *id,
    char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
    char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
    char res[AKA_RES_MAX], int *res_len)
{
    if (!http_get_auth_data(rand, autn, res, ck, ik, res_len)) {
        return FAILED;
    }
    return SUCCESS;
}

METHOD(eap_sim_http_card_t, destroy, void,
    private_eap_sim_http_card_t *this)
{
    free(this);
}

eap_sim_http_card_t *eap_sim_http_card_create()
{
    private_eap_sim_http_card_t *this;

    INIT(this,
        .public = {
            .card = {
                .get_triplet = (void*)return_false,
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
