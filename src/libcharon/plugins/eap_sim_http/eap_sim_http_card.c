#include "eap_sim_http_card.h"

#include <daemon.h>
#include <sa/ike_sa.h>
#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct private_eap_sim_http_card_t private_eap_sim_http_card_t;

/**
 * Private data of an eap_sim_http_card_t object.
 */
struct private_eap_sim_http_card_t {
    /**
     * Public eap_sim_http_card_t interface.
     */
    eap_sim_http_card_t public;

	char *url;

    char auts[AKA_AUTS_LEN];
};

/**
 * Structure to store HTTP response
 */
struct http_response {
    char *data;
    size_t size;
};

/**
 * Callback for storing HTTP response
 */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct http_response *response = (struct http_response *)userdata;
    size_t realsize = size * nmemb;

    response->data = realloc(response->data, response->size + realsize + 1);
    if (response->data == NULL) {
        return 0;  /* out of memory */
    }

    memcpy(&(response->data[response->size]), ptr, realsize);
    response->size += realsize;
    response->data[response->size] = 0;

    return realsize;
}

/**
 * Parse JSON response from HTTP server
 * Expected format: {"res":"HEXSTRING","ck":"HEXSTRING","ik":"HEXSTRING"}
 */
static bool parse_json_response(char *json, char *res, int *res_len,
                              char *ck, char *ik)
{
    char *ptr;
    char *clean_json;
    char hex[3] = {0};
    int i, j;
    char res_str[AKA_RES_MAX * 2 + 1] = {0};  // Buffer for string representation
    char ck_str[AKA_CK_LEN * 2 + 1] = {0};    // Buffer for string representation
    char ik_str[AKA_IK_LEN * 2 + 1] = {0};    // Buffer for string representation

    /* Create a clean copy without spaces or linebreaks */
    clean_json = malloc(strlen(json) + 1);
    if (!clean_json) return FALSE;

    /* Copy while removing whitespace */
    for (i = 0, j = 0; json[i]; i++) {
        if (json[i] != ' ' && json[i] != '\t' && json[i] != '\n' && json[i] != '\r') {
            clean_json[j++] = json[i];
        }
    }
    clean_json[j] = '\0';

    DBG1(DBG_IKE, "Finding RES");
    /* Find RES */
    ptr = strstr(clean_json, "\"res\":\"");
    if (!ptr) {
        free(clean_json);
        return FALSE;
    }
    ptr += 7;

    /* Copy the original hex string for logging */
    for (i = 0; i < AKA_RES_MAX * 2 && ptr[i] && ptr[i] != '"'; i++) {
        res_str[i] = ptr[i];
    }
    res_str[i] = '\0';

    /* Parse RES hex string */
    for (i = 0; i < AKA_RES_MAX && ptr[i*2] && ptr[i*2+1] && ptr[i*2] != '"'; i++) {
        hex[0] = ptr[i*2];
        hex[1] = ptr[i*2+1];
        res[i] = (char)strtol(hex, NULL, 16);
    }
    *res_len = i;
    res[i] = '\0';  // Null-terminate for safe printing

    DBG1(DBG_IKE, "RES: %s", res_str);

    DBG1(DBG_IKE, "Finding CK");
    /* Find CK */
    ptr = strstr(clean_json, "\"ck\":\"");
    if (!ptr) {
        free(clean_json);
        return FALSE;
    }
    ptr += 6;

    /* Copy the original hex string for logging */
    for (i = 0; i < AKA_CK_LEN * 2 && ptr[i] && ptr[i] != '"'; i++) {
        ck_str[i] = ptr[i];
    }
    ck_str[i] = '\0';

    /* Parse CK hex string */
    for (i = 0; i < AKA_CK_LEN && ptr[i*2] && ptr[i*2+1] && ptr[i*2] != '"'; i++) {
        hex[0] = ptr[i*2];
        hex[1] = ptr[i*2+1];
        ck[i] = (char)strtol(hex, NULL, 16);
    }
    if (i != AKA_CK_LEN) {
        free(clean_json);
        return FALSE;
    }
    ck[i] = '\0';  // Null-terminate for safe printing

    DBG1(DBG_IKE, "CK: %s", ck_str);

    /* Find IK */
    DBG1(DBG_IKE, "Finding IK");
    ptr = strstr(clean_json, "\"ik\":\"");
    if (!ptr) {
        free(clean_json);
        return FALSE;
    }
    ptr += 6;

    /* Copy the original hex string for logging */
    for (i = 0; i < AKA_IK_LEN * 2 && ptr[i] && ptr[i] != '"'; i++) {
        ik_str[i] = ptr[i];
    }
    ik_str[i] = '\0';

    /* Parse IK hex string */
    for (i = 0; i < AKA_IK_LEN && ptr[i*2] && ptr[i*2+1] && ptr[i*2] != '"'; i++) {
        hex[0] = ptr[i*2];
        hex[1] = ptr[i*2+1];
        ik[i] = (char)strtol(hex, NULL, 16);
    }
    if (i != AKA_IK_LEN) {
        free(clean_json);
        return FALSE;
    }
    ik[i] = '\0';  // Null-terminate for safe printing

    DBG1(DBG_IKE, "IK: %s", ik_str);
    DBG1(DBG_IKE, "Done parsing");

    free(clean_json);
    return TRUE;
}

char* readfile(FILE *f) {
	// f invalid? fseek() fail?
	if (f == NULL || fseek(f, 0, SEEK_END)) {
	  return NULL;
	}

	long length = ftell(f);
	rewind(f);
	// Did ftell() fail?  Is the length too long?
	if (length == -1 || (unsigned long) length >= SIZE_MAX) {
	  return NULL;
	}

	// Convert from long to size_t
	size_t ulength = (size_t) length;
	char *buffer = malloc(ulength + 1);
	// Allocation failed? Read incomplete?
	if (buffer == NULL || fread(buffer, 1, ulength, f) != ulength) {
	  free(buffer);
	  return NULL;
	}
	buffer[ulength] = '\0'; // Now buffer points to a string

	return buffer;
}

METHOD(simaka_card_t, get_quintuplet, status_t,
    private_eap_sim_http_card_t *this, identification_t *id,
    char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
    char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
    CURL *curl;
    CURLcode res_code;
    struct http_response response = {0};
    char url[512];
    char config_url[512];
    char rand_hex[AKA_RAND_LEN*2 + 1] = {0};
    char autn_hex[AKA_AUTN_LEN*2 + 1] = {0};
    int i;
    status_t status = FAILED;
    char filename[256];

    /* Convert RAND and AUTN to hex strings */
    for (i = 0; i < AKA_RAND_LEN; i++) {
        snprintf(&rand_hex[i*2], 3, "%02x", (unsigned char)rand[i]);
    }
    for (i = 0; i < AKA_AUTN_LEN; i++) {
        snprintf(&autn_hex[i*2], 3, "%02x", (unsigned char)autn[i]);
    }

	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
    if (!ike_sa) {
        DBG1(DBG_IKE, "Failed to get IKE SA");
        return FAILED;
    }

    /* Build filename using IKE SA name */
    snprintf(filename, sizeof(filename), "/etc/ims_%s.url", ike_sa->get_name(ike_sa));
    DBG1(DBG_IKE, "Reading URL from file: '%s'", filename);

	FILE * f = fopen (filename, "r");
	char * _config_url = readfile(f);
	fclose(f);
	if (!_config_url) {
		DBG1(DBG_IKE, "Failed to read URL from file");
		return FAILED;
	}
	_config_url[strcspn(_config_url, "\r\n")] = 0;

	DBG1(DBG_IKE, "Raw URL from file: %s", _config_url);
	if (snprintf(config_url, sizeof(config_url), "%s", _config_url) >= sizeof(config_url)) {
		DBG1(DBG_IKE, "URL too long");
		free(_config_url);
		return FAILED;
	}
	free(_config_url);

    /* Build URL */
    snprintf(url, sizeof(url), "%s/?type=rand-autn&rand=%s&autn=%s",
		config_url, rand_hex, autn_hex);

	DBG1(DBG_IKE, "Init CURL client to url: '%s'", url);

    curl = curl_easy_init();
    if (!curl) {
        return FAILED;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    res_code = curl_easy_perform(curl);
    if (res_code != CURLE_OK) {
        DBG1(DBG_IKE, "HTTP request to '%s' failed with error: '%s'", url, curl_easy_strerror(res_code));
        goto cleanup;
    }

    if (!parse_json_response(response.data, res, res_len, ck, ik)) {
		DBG1(DBG_IKE, "Failed to parse JSON");
        DBG1(DBG_IKE, "Failed to parse JSON response: '%s'", response.data);
        goto cleanup;
    }
	DBG1(DBG_IKE, "Parsed: %s", response.data);
    status = SUCCESS;

cleanup:
    curl_easy_cleanup(curl);
    free(response.data);
    return status;
}

METHOD(simaka_card_t, get_triplet, bool,
    private_eap_sim_http_card_t *this, identification_t *id,
    char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN])
{
    return FALSE;
}

METHOD(simaka_card_t, resync, bool,
    private_eap_sim_http_card_t *this, identification_t *id,
    char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
    return FALSE;
}

METHOD(eap_sim_http_card_t, destroy, void,
    private_eap_sim_http_card_t *this)
{
    free(this);
}

/**
 * See header
 */
eap_sim_http_card_t *eap_sim_http_card_create()
{
    private_eap_sim_http_card_t *this;

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
