/*
 * Copyright (C) 2008-2020 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

#include <library.h>
#include <utils/debug.h>
#include <collections/array.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/thread_value.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include "openssl_plugin.h"
#include "openssl_util.h"
#include "openssl_crypter.h"
#include "openssl_hasher.h"
#include "openssl_sha1_prf.h"
#include "openssl_diffie_hellman.h"
#include "openssl_ec_diffie_hellman.h"
#include "openssl_rsa_private_key.h"
#include "openssl_rsa_public_key.h"
#include "openssl_ec_private_key.h"
#include "openssl_ec_public_key.h"
#include "openssl_x509.h"
#include "openssl_crl.h"
#include "openssl_pkcs7.h"
#include "openssl_pkcs12.h"
#include "openssl_rng.h"
#include "openssl_hmac.h"
#include "openssl_aead.h"
#include "openssl_x_diffie_hellman.h"
#include "openssl_ed_public_key.h"
#include "openssl_ed_private_key.h"
#include "openssl_xof.h"

#ifndef FIPS_MODE
#define FIPS_MODE 0
#endif

typedef struct private_openssl_plugin_t private_openssl_plugin_t;

/**
 * private data of openssl_plugin
 */
struct private_openssl_plugin_t {

	/**
	 * public functions
	 */
	openssl_plugin_t public;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/**
	 * Loaded providers
	 */
	array_t *providers;
#endif
};

/**
 * OpenSSL is thread-safe since 1.1.0
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

/**
 * Array of static mutexes, with CRYPTO_num_locks() mutex
 */
static mutex_t **mutex = NULL;

/**
 * Locking callback for static locks
 */
static void locking_function(int mode, int type, const char *file, int line)
{
	if (mutex)
	{
		if (mode & CRYPTO_LOCK)
		{
			mutex[type]->lock(mutex[type]);
		}
		else
		{
			mutex[type]->unlock(mutex[type]);
		}
	}
}

/**
 * Implementation of dynlock
 */
struct CRYPTO_dynlock_value {
	mutex_t *mutex;
};

/**
 * Callback to create a dynamic lock
 */
static struct CRYPTO_dynlock_value *create_function(const char *file, int line)
{
	struct CRYPTO_dynlock_value *lock;

	lock = malloc_thing(struct CRYPTO_dynlock_value);
	lock->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	return lock;
}

/**
 * Callback to (un-)lock a dynamic lock
 */
static void lock_function(int mode, struct CRYPTO_dynlock_value *lock,
						  const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		lock->mutex->lock(lock->mutex);
	}
	else
	{
		lock->mutex->unlock(lock->mutex);
	}
}

/**
 * Callback to destroy a dynamic lock
 */
static void destroy_function(struct CRYPTO_dynlock_value *lock,
							 const char *file, int line)
{
	lock->mutex->destroy(lock->mutex);
	free(lock);
}

/**
 * Thread-local value used to cleanup thread-specific error buffers
 */
static thread_value_t *cleanup;

/**
 * Called when a thread is destroyed. Avoid recursion by setting the thread id
 * explicitly.
 */
static void cleanup_thread(void *arg)
{
#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
	CRYPTO_THREADID tid;

	CRYPTO_THREADID_set_numeric(&tid, (u_long)(uintptr_t)arg);
	ERR_remove_thread_state(&tid);
#else
	ERR_remove_state((u_long)(uintptr_t)arg);
#endif
}

/**
 * Thread-ID callback function
 */
static u_long id_function(void)
{
	u_long id;

	/* ensure the thread ID is never zero, otherwise OpenSSL might try to
	 * acquire locks recursively */
	id = 1 + (u_long)thread_current_id();

	/* cleanup a thread's state later if OpenSSL interacted with it */
	cleanup->set(cleanup, (void*)(uintptr_t)id);
	return id;
}

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
/**
 * Callback for thread ID
 */
static void threadid_function(CRYPTO_THREADID *threadid)
{
	CRYPTO_THREADID_set_numeric(threadid, id_function());
}
#endif /* OPENSSL_VERSION_NUMBER */

/**
 * initialize OpenSSL for multi-threaded use
 */
static void threading_init()
{
	int i, num_locks;

	cleanup = thread_value_create(cleanup_thread);

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
	CRYPTO_THREADID_set_callback(threadid_function);
#else
	CRYPTO_set_id_callback(id_function);
#endif

	CRYPTO_set_locking_callback(locking_function);

	CRYPTO_set_dynlock_create_callback(create_function);
	CRYPTO_set_dynlock_lock_callback(lock_function);
	CRYPTO_set_dynlock_destroy_callback(destroy_function);

	num_locks = CRYPTO_num_locks();
	mutex = malloc(sizeof(mutex_t*) * num_locks);
	for (i = 0; i < num_locks; i++)
	{
		mutex[i] = mutex_create(MUTEX_TYPE_DEFAULT);
	}
}

/**
 * cleanup OpenSSL threading locks
 */
static void threading_cleanup()
{
	int i, num_locks;

	num_locks = CRYPTO_num_locks();
	for (i = 0; i < num_locks; i++)
	{
		mutex[i]->destroy(mutex[i]);
	}
	free(mutex);
	mutex = NULL;

	cleanup->destroy(cleanup);
}

#else /* OPENSSL_VERSION_NUMBER */

#define threading_init()

#define threading_cleanup()

#endif

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
/**
 * Seed the OpenSSL RNG, if required
 * Not necessary anymore with OpenSSL 1.1.1 (maybe wasn't already earlier, but
 * it's now explicitly mentioned in the documentation).
 */
static bool seed_rng()
{
	rng_t *rng = NULL;
	char buf[32];

	while (RAND_status() != 1)
	{
		if (!rng)
		{
			rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
			if (!rng)
			{
				return FALSE;
			}
		}
		if (!rng->get_bytes(rng, sizeof(buf), buf))
		{
			rng->destroy(rng);
			return FALSE;
		}
		RAND_seed(buf, sizeof(buf));
	}
	DESTROY_IF(rng);
	return TRUE;
}
#endif /* OPENSSL_VERSION_NUMBER */

/**
 * Generic key loader
 */
static private_key_t *openssl_private_key_load(key_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;
	EVP_PKEY *key;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (blob.ptr)
	{
		key = d2i_AutoPrivateKey(NULL, (const u_char**)&blob.ptr, blob.len);
		if (key)
		{
			switch (EVP_PKEY_base_id(key))
			{
#ifndef OPENSSL_NO_RSA
				case EVP_PKEY_RSA:
					return openssl_rsa_private_key_create(key, FALSE);
#endif
#ifndef OPENSSL_NO_ECDSA
				case EVP_PKEY_EC:
					return openssl_ec_private_key_create(key, FALSE);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_EC)
				case EVP_PKEY_ED25519:
				case EVP_PKEY_ED448:
					return openssl_ed_private_key_create(key, FALSE);
#endif /* OPENSSL_VERSION_NUMBER */
				default:
					EVP_PKEY_free(key);
					break;
			}
		}
	}
	return NULL;
}

#ifndef OPENSSL_NO_ENGINE
/**
 * Login to engine with a PIN specified for a keyid
 */
static bool login(ENGINE *engine, chunk_t keyid)
{
	enumerator_t *enumerator;
	shared_key_t *shared;
	identification_t *id;
	chunk_t key;
	char pin[64];
	bool found = FALSE, success = FALSE;

	id = identification_create_from_encoding(ID_KEY_ID, keyid);
	enumerator = lib->credmgr->create_shared_enumerator(lib->credmgr,
														SHARED_PIN, id, NULL);
	while (enumerator->enumerate(enumerator, &shared, NULL, NULL))
	{
		found = TRUE;
		key = shared->get_key(shared);
		if (snprintf(pin, sizeof(pin),
					 "%.*s", (int)key.len, key.ptr) >= sizeof(pin))
		{
			continue;
		}
		if (ENGINE_ctrl_cmd_string(engine, "PIN", pin, 0))
		{
			success = TRUE;
			break;
		}
		else
		{
			DBG1(DBG_CFG, "setting PIN on engine failed");
		}
	}
	enumerator->destroy(enumerator);
	id->destroy(id);
	if (!found)
	{
		DBG1(DBG_CFG, "no PIN found for %#B", &keyid);
	}
	return success;
}
#endif /* OPENSSL_NO_ENGINE */

/**
 * Load private key via engine
 */
static private_key_t *openssl_private_key_connect(key_type_t type,
												  va_list args)
{
#ifndef OPENSSL_NO_ENGINE
	char *engine_id = NULL;
	char keyname[BUF_LEN];
	chunk_t keyid = chunk_empty;
	EVP_PKEY *key;
	ENGINE *engine;
	int slot = -1;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_PKCS11_KEYID:
				keyid = va_arg(args, chunk_t);
				continue;
			case BUILD_PKCS11_SLOT:
				slot = va_arg(args, int);
				continue;
			case BUILD_PKCS11_MODULE:
				engine_id = va_arg(args, char*);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (!keyid.len)
	{
		return NULL;
	}

	memset(keyname, 0, sizeof(keyname));
	if (slot != -1)
	{
		snprintf(keyname, sizeof(keyname), "%d:", slot);
	}
	if (sizeof(keyname) - strlen(keyname) <= keyid.len * 2 + 1)
	{
		return NULL;
	}
	chunk_to_hex(keyid, keyname + strlen(keyname), FALSE);

	if (!engine_id)
	{
		engine_id = lib->settings->get_str(lib->settings,
							"%s.plugins.openssl.engine_id", "pkcs11", lib->ns);
	}
	engine = ENGINE_by_id(engine_id);
	if (!engine)
	{
		DBG2(DBG_LIB, "engine '%s' is not available", engine_id);
		return NULL;
	}
	if (!ENGINE_init(engine))
	{
		DBG1(DBG_LIB, "failed to initialize engine '%s'", engine_id);
		ENGINE_free(engine);
		return NULL;
	}
	ENGINE_free(engine);
	if (!login(engine, keyid))
	{
		DBG1(DBG_LIB, "login to engine '%s' failed", engine_id);
		ENGINE_finish(engine);
		return NULL;
	}
	key = ENGINE_load_private_key(engine, keyname, NULL, NULL);
	ENGINE_finish(engine);
	if (!key)
	{
		DBG1(DBG_LIB, "failed to load private key with ID '%s' from "
			 "engine '%s'", keyname, engine_id);
		return NULL;
	}

	switch (EVP_PKEY_base_id(key))
	{
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			return openssl_rsa_private_key_create(key, TRUE);
#endif
#ifndef OPENSSL_NO_ECDSA
		case EVP_PKEY_EC:
			return openssl_ec_private_key_create(key, TRUE);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_EC)
		case EVP_PKEY_ED25519:
		case EVP_PKEY_ED448:
			return openssl_ed_private_key_create(key, TRUE);
#endif /* OPENSSL_VERSION_NUMBER */
		default:
			EVP_PKEY_free(key);
			break;
	}
#endif /* OPENSSL_NO_ENGINE */
	return NULL;
}

METHOD(plugin_t, get_name, char*,
	private_openssl_plugin_t *this)
{
	return "openssl";
}

METHOD(plugin_t, get_features, int,
	private_openssl_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		/* we provide OpenSSL threading callbacks */
		PLUGIN_PROVIDE(CUSTOM, "openssl-threading"),
		/* crypters */
		PLUGIN_REGISTER(CRYPTER, openssl_crypter_create),
#ifndef OPENSSL_NO_AES
			PLUGIN_PROVIDE(CRYPTER, ENCR_AES_CBC, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_AES_CBC, 24),
			PLUGIN_PROVIDE(CRYPTER, ENCR_AES_CBC, 32),
			PLUGIN_PROVIDE(CRYPTER, ENCR_AES_ECB, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_AES_ECB, 24),
			PLUGIN_PROVIDE(CRYPTER, ENCR_AES_ECB, 32),
#endif
#ifndef OPENSSL_NO_CAMELLIA
			PLUGIN_PROVIDE(CRYPTER, ENCR_CAMELLIA_CBC, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_CAMELLIA_CBC, 24),
			PLUGIN_PROVIDE(CRYPTER, ENCR_CAMELLIA_CBC, 32),
#endif
#ifndef OPENSSL_NO_RC5
			PLUGIN_PROVIDE(CRYPTER, ENCR_RC5, 0),
#endif
#ifndef OPENSSL_NO_CAST
			PLUGIN_PROVIDE(CRYPTER, ENCR_CAST, 0),
#endif
#ifndef OPENSSL_NO_BLOWFISH
			PLUGIN_PROVIDE(CRYPTER, ENCR_BLOWFISH, 0),
#endif
#ifndef OPENSSL_NO_IDEA
			PLUGIN_PROVIDE(CRYPTER, ENCR_IDEA, 16),
#endif
#ifndef OPENSSL_NO_DES
			PLUGIN_PROVIDE(CRYPTER, ENCR_3DES, 24),
			PLUGIN_PROVIDE(CRYPTER, ENCR_DES, 8),
			PLUGIN_PROVIDE(CRYPTER, ENCR_DES_ECB, 8),
#endif
			PLUGIN_PROVIDE(CRYPTER, ENCR_NULL, 0),
		/* hashers */
		PLUGIN_REGISTER(HASHER, openssl_hasher_create),
#ifndef OPENSSL_NO_MD2
			PLUGIN_PROVIDE(HASHER, HASH_MD2),
#endif
#ifndef OPENSSL_NO_MD4
			PLUGIN_PROVIDE(HASHER, HASH_MD4),
#endif
#ifndef OPENSSL_NO_MD5
			PLUGIN_PROVIDE(HASHER, HASH_MD5),
#endif
#ifndef OPENSSL_NO_SHA1
			PLUGIN_PROVIDE(HASHER, HASH_SHA1),
#endif
#ifndef OPENSSL_NO_SHA256
			PLUGIN_PROVIDE(HASHER, HASH_SHA224),
			PLUGIN_PROVIDE(HASHER, HASH_SHA256),
#endif
#ifndef OPENSSL_NO_SHA512
			PLUGIN_PROVIDE(HASHER, HASH_SHA384),
			PLUGIN_PROVIDE(HASHER, HASH_SHA512),
#endif
/* SHA3/SHAKE was added with OpenSSL 1.1.1, it doesn't seem to be possible to
 * disable it, defining the checked var prevents registration, though */
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_SHA3)
			PLUGIN_PROVIDE(HASHER, HASH_SHA3_224),
			PLUGIN_PROVIDE(HASHER, HASH_SHA3_256),
			PLUGIN_PROVIDE(HASHER, HASH_SHA3_384),
			PLUGIN_PROVIDE(HASHER, HASH_SHA3_512),
#endif
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_SHAKE)
		PLUGIN_REGISTER(XOF, openssl_xof_create),
			PLUGIN_PROVIDE(XOF, XOF_SHAKE_128),
			PLUGIN_PROVIDE(XOF, XOF_SHAKE_256),
#endif
#ifndef OPENSSL_NO_SHA1
		/* keyed sha1 hasher (aka prf) */
		PLUGIN_REGISTER(PRF, openssl_sha1_prf_create),
			PLUGIN_PROVIDE(PRF, PRF_KEYED_SHA1),
#endif
#ifndef OPENSSL_NO_HMAC
		PLUGIN_REGISTER(PRF, openssl_hmac_prf_create),
#ifndef OPENSSL_NO_MD5
			PLUGIN_PROVIDE(PRF, PRF_HMAC_MD5),
#endif
#ifndef OPENSSL_NO_SHA1
			PLUGIN_PROVIDE(PRF, PRF_HMAC_SHA1),
#endif
#ifndef OPENSSL_NO_SHA256
			PLUGIN_PROVIDE(PRF, PRF_HMAC_SHA2_256),
#endif
#ifndef OPENSSL_NO_SHA512
			PLUGIN_PROVIDE(PRF, PRF_HMAC_SHA2_384),
			PLUGIN_PROVIDE(PRF, PRF_HMAC_SHA2_512),
#endif
		PLUGIN_REGISTER(SIGNER, openssl_hmac_signer_create),
#ifndef OPENSSL_NO_MD5
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_MD5_96),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_MD5_128),
#endif
#ifndef OPENSSL_NO_SHA1
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA1_96),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA1_128),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA1_160),
#endif
#ifndef OPENSSL_NO_SHA256
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA2_256_128),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA2_256_256),
#endif
#ifndef OPENSSL_NO_SHA512
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA2_384_192),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA2_384_384),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA2_512_256),
			PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SHA2_512_512),
#endif
#endif /* OPENSSL_NO_HMAC */
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_AES)) || \
	(OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined(OPENSSL_NO_CHACHA))
		/* AEAD (AES GCM since 1.0.1, ChaCha20-Poly1305 since 1.1.0) */
		PLUGIN_REGISTER(AEAD, openssl_aead_create),
#ifndef OPENSSL_NO_AES
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV16, 16),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV16, 24),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV16, 32),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV12, 16),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV12, 24),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV12, 32),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV8,  16),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV8,  24),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_GCM_ICV8,  32),
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
			/* CCM is available before 1.1.0 but not via generic controls */
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV16, 16),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV16, 24),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV16, 32),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV12, 16),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV12, 24),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV12, 32),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV8,  16),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV8,  24),
			PLUGIN_PROVIDE(AEAD, ENCR_AES_CCM_ICV8,  32),
#endif /* OPENSSL_VERSION_NUMBER */
#endif /* OPENSSL_NO_AES */
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined(OPENSSL_NO_CHACHA)
			PLUGIN_PROVIDE(AEAD, ENCR_CHACHA20_POLY1305, 32),
#endif /* OPENSSL_NO_CHACHA */
#endif /* OPENSSL_VERSION_NUMBER */
#ifndef OPENSSL_NO_ECDH
		/* EC DH groups */
		PLUGIN_REGISTER(DH, openssl_ec_diffie_hellman_create),
			PLUGIN_PROVIDE(DH, ECP_256_BIT),
			PLUGIN_PROVIDE(DH, ECP_384_BIT),
			PLUGIN_PROVIDE(DH, ECP_521_BIT),
			PLUGIN_PROVIDE(DH, ECP_224_BIT),
			PLUGIN_PROVIDE(DH, ECP_192_BIT),
			PLUGIN_PROVIDE(DH, ECP_256_BP),
			PLUGIN_PROVIDE(DH, ECP_384_BP),
			PLUGIN_PROVIDE(DH, ECP_512_BP),
			PLUGIN_PROVIDE(DH, ECP_224_BP),
#endif /* OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_DH
		/* MODP DH groups */
		PLUGIN_REGISTER(DH, openssl_diffie_hellman_create),
			PLUGIN_PROVIDE(DH, MODP_3072_BIT),
			PLUGIN_PROVIDE(DH, MODP_4096_BIT),
			PLUGIN_PROVIDE(DH, MODP_6144_BIT),
			PLUGIN_PROVIDE(DH, MODP_8192_BIT),
			PLUGIN_PROVIDE(DH, MODP_2048_BIT),
			PLUGIN_PROVIDE(DH, MODP_2048_224),
			PLUGIN_PROVIDE(DH, MODP_2048_256),
			PLUGIN_PROVIDE(DH, MODP_1536_BIT),
			PLUGIN_PROVIDE(DH, MODP_1024_BIT),
			PLUGIN_PROVIDE(DH, MODP_1024_160),
			PLUGIN_PROVIDE(DH, MODP_768_BIT),
			PLUGIN_PROVIDE(DH, MODP_CUSTOM),
#endif
#ifndef OPENSSL_NO_RSA
		/* RSA private/public key loading */
		PLUGIN_REGISTER(PRIVKEY, openssl_rsa_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_RSA),
		PLUGIN_REGISTER(PRIVKEY_GEN, openssl_rsa_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_RSA),
		PLUGIN_REGISTER(PUBKEY, openssl_rsa_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_RSA),
		PLUGIN_REGISTER(PUBKEY, openssl_rsa_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_ANY),
		/* signature/encryption schemes */
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_NULL),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_NULL),
#if OPENSSL_VERSION_NUMBER >=  0x10000000L
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PSS),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PSS),
#endif
#ifndef OPENSSL_NO_SHA1
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA1),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA1),
#endif
#ifndef OPENSSL_NO_SHA256
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA2_224),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA2_256),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA2_224),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA2_256),
#endif
#ifndef OPENSSL_NO_SHA512
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA2_384),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA2_512),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA2_384),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA2_512),
#endif
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_SHA3)
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA3_224),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA3_256),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA3_384),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_SHA3_512),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA3_224),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA3_256),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA3_384),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA3_512),
#endif
#ifndef OPENSSL_NO_MD5
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_RSA_EMSA_PKCS1_MD5),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_MD5),
#endif
		PLUGIN_PROVIDE(PRIVKEY_DECRYPT, ENCRYPT_RSA_PKCS1),
		PLUGIN_PROVIDE(PUBKEY_ENCRYPT, ENCRYPT_RSA_PKCS1),
#endif /* OPENSSL_NO_RSA */
		/* certificate/CRL loading */
		PLUGIN_REGISTER(CERT_DECODE, openssl_x509_load, TRUE),
			PLUGIN_PROVIDE(CERT_DECODE, CERT_X509),
				PLUGIN_SDEPEND(PUBKEY, KEY_RSA),
				PLUGIN_SDEPEND(PUBKEY, KEY_ECDSA),
				PLUGIN_SDEPEND(PUBKEY, KEY_DSA),
		PLUGIN_REGISTER(CERT_DECODE, openssl_crl_load, TRUE),
			PLUGIN_PROVIDE(CERT_DECODE, CERT_X509_CRL),
#if OPENSSL_VERSION_NUMBER >= 0x0090807fL
#ifndef OPENSSL_NO_CMS
		PLUGIN_REGISTER(CONTAINER_DECODE, openssl_pkcs7_load, TRUE),
			PLUGIN_PROVIDE(CONTAINER_DECODE, CONTAINER_PKCS7),
#endif /* OPENSSL_NO_CMS */
#endif /* OPENSSL_VERSION_NUMBER */
		PLUGIN_REGISTER(CONTAINER_DECODE, openssl_pkcs12_load, TRUE),
			PLUGIN_PROVIDE(CONTAINER_DECODE, CONTAINER_PKCS12),
#ifndef OPENSSL_NO_ECDSA
		/* EC private/public key loading */
		PLUGIN_REGISTER(PRIVKEY, openssl_ec_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ECDSA),
		PLUGIN_REGISTER(PRIVKEY_GEN, openssl_ec_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_ECDSA),
		PLUGIN_REGISTER(PUBKEY, openssl_ec_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_ECDSA),
		/* signature encryption schemes */
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_WITH_NULL),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_WITH_NULL),
#ifndef OPENSSL_NO_SHA1
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_WITH_SHA1_DER),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_WITH_SHA1_DER),
#endif
#ifndef OPENSSL_NO_SHA256
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_WITH_SHA256_DER),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_WITH_SHA256_DER),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_256),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_256),
#endif
#ifndef OPENSSL_NO_SHA512
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_WITH_SHA384_DER),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_WITH_SHA512_DER),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_WITH_SHA384_DER),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_WITH_SHA512_DER),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_384),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ECDSA_521),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_384),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ECDSA_521),
#endif
#endif /* OPENSSL_NO_ECDSA */
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_ECDH)
		PLUGIN_REGISTER(DH, openssl_x_diffie_hellman_create),
			/* available since 1.1.0a, but we require 1.1.1 features */
			PLUGIN_PROVIDE(DH, CURVE_25519),
			/* available since 1.1.1 */
			PLUGIN_PROVIDE(DH, CURVE_448),
#endif /* OPENSSL_VERSION_NUMBER && !OPENSSL_NO_ECDH */
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(OPENSSL_NO_EC)
		/* EdDSA private/public key loading */
		PLUGIN_REGISTER(PUBKEY, openssl_ed_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_ED25519),
			PLUGIN_PROVIDE(PUBKEY, KEY_ED448),
		PLUGIN_REGISTER(PRIVKEY, openssl_ed_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ED25519),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ED448),
		PLUGIN_REGISTER(PRIVKEY_GEN, openssl_ed_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_ED25519),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_ED448),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ED25519),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ED448),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ED25519),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ED448),
		/* register a pro forma identity hasher, never instantiated */
		PLUGIN_REGISTER(HASHER, return_null),
			PLUGIN_PROVIDE(HASHER, HASH_IDENTITY),
#endif /* OPENSSL_VERSION_NUMBER && !OPENSSL_NO_EC */
		/* generic key loader */
		PLUGIN_REGISTER(PRIVKEY, openssl_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ANY),
		PLUGIN_REGISTER(PRIVKEY, openssl_private_key_connect, FALSE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ANY),
		PLUGIN_REGISTER(RNG, openssl_rng_create),
			PLUGIN_PROVIDE(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(RNG, RNG_WEAK),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_openssl_plugin_t *this)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OSSL_PROVIDER *provider;
	while (array_remove(this->providers, ARRAY_TAIL, &provider))
	{
		OSSL_PROVIDER_unload(provider);
	}
	array_destroy(this->providers);
#endif /* OPENSSL_VERSION_NUMBER */

/* OpenSSL 1.1.0 cleans up itself at exit and while OPENSSL_cleanup() exists we
 * can't call it as we couldn't re-initialize the library (as required by the
 * unit tests and the Android app) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef OPENSSL_IS_BORINGSSL
	CONF_modules_free();
	OBJ_cleanup();
#endif
	EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif /* OPENSSL_NO_ENGINE */
	CRYPTO_cleanup_all_ex_data();
	threading_cleanup();
	ERR_free_strings();
#endif /* OPENSSL_VERSION_NUMBER */

	free(this);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
typedef struct {
	char names[BUF_LEN];
	int len;
} ossl_provider_names_t;

/**
 * Callback to produce a list of the names of loaded providers
 */
static int concat_ossl_providers(OSSL_PROVIDER *provider, void *cbdata)
{
	ossl_provider_names_t *data = cbdata;
	int len;

	len = snprintf(&data->names[data->len], sizeof(data->names) - data->len,
				   " %s", OSSL_PROVIDER_get0_name(provider));
	if (len < (sizeof(data->names) - data->len))
	{
		data->len += len;
		return 1;
	}
	return 0;
}
#endif

/*
 * see header file
 */
plugin_t *openssl_plugin_create()
{
	private_openssl_plugin_t *this;
	int fips_mode;

	fips_mode = lib->settings->get_int(lib->settings,
							"%s.plugins.openssl.fips_mode", FIPS_MODE, lib->ns);
#ifdef OPENSSL_FIPS
	if (fips_mode)
	{
		if (FIPS_mode() != fips_mode && !FIPS_mode_set(fips_mode))
		{
			DBG1(DBG_LIB, "unable to set OpenSSL FIPS mode(%d) from (%d)",
				 fips_mode, FIPS_mode());
			return NULL;
		}
	}
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
	/* OpenSSL 3.0+ is handled below */
	if (fips_mode)
	{
		DBG1(DBG_LIB, "OpenSSL FIPS mode(%d) unavailable", fips_mode);
		return NULL;
	}
#endif

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* note that we can't call OPENSSL_cleanup() when the plugin is destroyed
	 * as we couldn't initialize the library again afterwards */
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG |
						OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
#else /* OPENSSL_VERSION_NUMBER */
	threading_init();
#ifndef OPENSSL_IS_BORINGSSL
	OPENSSL_config(NULL);
#endif
	OpenSSL_add_all_algorithms();
#ifndef OPENSSL_NO_ENGINE
	/* activate support for hardware accelerators */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif /* OPENSSL_NO_ENGINE */
#endif /* OPENSSL_VERSION_NUMBER */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (fips_mode)
	{
		OSSL_PROVIDER *fips;

		fips = OSSL_PROVIDER_load(NULL, "fips");
		if (!fips)
		{
			DBG1(DBG_LIB, "unable to load OpenSSL FIPS provider");
			return NULL;
		}
		array_insert_create(&this->providers, ARRAY_TAIL, fips);
		/* explicitly load the base provider containing encoding functions */
		array_insert_create(&this->providers, ARRAY_TAIL,
							OSSL_PROVIDER_load(NULL, "base"));
	}
	else if (lib->settings->get_bool(lib->settings, "%s.plugins.openssl.load_legacy",
									 TRUE, lib->ns))
	{
		/* load the legacy provider for algorithms like MD4, DES, BF etc. */
		array_insert_create(&this->providers, ARRAY_TAIL,
							OSSL_PROVIDER_load(NULL, "legacy"));
		/* explicitly load the default provider, as mentioned by crypto(7) */
		array_insert_create(&this->providers, ARRAY_TAIL,
							OSSL_PROVIDER_load(NULL, "default"));
	}
	ossl_provider_names_t data = {};
	OSSL_PROVIDER_do_all(NULL, concat_ossl_providers, &data);
	dbg(DBG_LIB, strpfx(lib->ns, "charon") ? 1 : 2,
		"providers loaded by OpenSSL:%s", data.names);
#endif /* OPENSSL_VERSION_NUMBER */

#ifdef OPENSSL_FIPS
	/* we do this here as it may have been enabled via openssl.conf */
	fips_mode = FIPS_mode();
	dbg(DBG_LIB, strpfx(lib->ns, "charon") ? 1 : 2,
		"OpenSSL FIPS mode(%d) - %sabled ", fips_mode, fips_mode ? "en" : "dis");
#endif /* OPENSSL_FIPS */

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
	if (!seed_rng())
	{
		DBG1(DBG_CFG, "no RNG found to seed OpenSSL");
		destroy(this);
		return NULL;
	}
#endif /* OPENSSL_VERSION_NUMBER */

	return &this->public.plugin;
}
