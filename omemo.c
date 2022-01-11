// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <sys/param.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <gcrypt.h>
#include <signal_protocol.h>
#include <key_helper.h>
#include <session_builder.h>
#include <session_cipher.h>
#include <session_pre_key.h>
#include <protocol.h>
#include <curve.h>
#include <lmdb.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

struct t_omemo_db {
    MDB_env *env;
    MDB_dbi dbi_omemo;
};

struct t_pre_key {
    const char *id;
    const char *public_key;
};

#include "plugin.hh"
#include "xmpp/stanza.h"
#include "account.h"
#include "omemo.h"
#include "util.h"

#define mdb_val_str(s) { \
    .mv_data = s, .mv_size = strlen(s), \
}

#define mdb_val_intptr(i) { \
    .mv_data = i, .mv_size = sizeof(*i), \
}

#define mdb_val_sizeof(t) { \
    .mv_data = NULL, .mv_size = sizeof(t), \
}

#define PRE_KEY_START 1
#define PRE_KEY_COUNT 100

#define AES_KEY_SIZE (16)
#define AES_IV_SIZE (12)

const char *OMEMO_ADVICE = "[OMEMO encrypted message (XEP-0384)]";

size_t base64_decode(const char *buffer, size_t length, uint8_t **result)
{
    *result = calloc(length + 1, sizeof(uint8_t));
    return weechat_string_base_decode(64, buffer, (char*)*result);
}

size_t base64_encode(const uint8_t *buffer, size_t length, char **result)
{
    *result = calloc(length * 2, sizeof(char));
    return weechat_string_base_encode(64, (char*)buffer, length, *result);
}

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *key, uint8_t *iv, uint8_t *tag, size_t tag_len,
                uint8_t **plaintext, size_t *plaintext_len)
{
    gcry_cipher_hd_t cipher = NULL;
    if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES128,
                GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_SECURE)) goto cleanup;
    if (gcry_cipher_setkey(cipher, key, AES_KEY_SIZE)) goto cleanup;
    if (gcry_cipher_setiv(cipher, iv, AES_IV_SIZE)) goto cleanup;
    *plaintext_len = ciphertext_len;
    *plaintext = malloc((sizeof(uint8_t) * *plaintext_len) + 1);
    if (gcry_cipher_decrypt(cipher, *plaintext, *plaintext_len,
                            ciphertext, ciphertext_len)) goto cleanup;
    if (gcry_cipher_checktag(cipher, tag, tag_len)) goto cleanup;
    gcry_cipher_close(cipher);
    return 1;
cleanup:
    gcry_cipher_close(cipher);
    return 0;
}

int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                uint8_t **key, uint8_t **iv, uint8_t **tag, size_t *tag_len,
                uint8_t **ciphertext, size_t *ciphertext_len)
{
    *tag_len = 16;
    *tag = calloc(*tag_len, sizeof(uint8_t));
    *iv = gcry_random_bytes(AES_IV_SIZE, GCRY_STRONG_RANDOM);
    *key = gcry_random_bytes(AES_KEY_SIZE, GCRY_STRONG_RANDOM);

    gcry_cipher_hd_t cipher = NULL;
    if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES128,
                GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_SECURE)) goto cleanup;
    if (gcry_cipher_setkey(cipher, *key, AES_KEY_SIZE)) goto cleanup;
    if (gcry_cipher_setiv(cipher, *iv, AES_IV_SIZE)) goto cleanup;
    *ciphertext_len = plaintext_len;
    *ciphertext = malloc((sizeof(uint8_t) * *ciphertext_len) + 1);
    if (gcry_cipher_encrypt(cipher, *ciphertext, *ciphertext_len,
                            plaintext, plaintext_len)) goto cleanup;
    if (gcry_cipher_gettag(cipher, *tag, *tag_len)) goto cleanup;
    gcry_cipher_close(cipher);
    return 1;
cleanup:
    gcry_cipher_close(cipher);
    return 0;
}

void signal_protocol_address_free(signal_protocol_address* ptr) {
    if (!ptr)
        return;
    if (ptr->name) {
        free((void*)ptr->name);
    }
    return free(ptr);
}

void signal_protocol_address_set_name(signal_protocol_address* self, const char* name) {
    if (!self)
        return;
    if (!name)
        return;
    char* n = malloc(strlen(name)+1);
    memcpy(n, name, strlen(name));
    n[strlen(name)] = 0;
    if (self->name) {
        free((void*)self->name);
    }
    self->name = n;
    self->name_len = strlen(n);
}

char* signal_protocol_address_get_name(signal_protocol_address* self) {
    if (!self)
        return NULL;
    if (!self->name)
        return 0;
    char* res = malloc(sizeof(char) * (self->name_len + 1));
    memcpy(res, self->name, self->name_len);
    res[self->name_len] = 0;
    return res;
}

int32_t signal_protocol_address_get_device_id(signal_protocol_address* self) {
    if (!self)
        return -1;
    return self->device_id;
}

void signal_protocol_address_set_device_id(signal_protocol_address* self, int32_t device_id) {
    if (!self)
        return;
    self->device_id = device_id;
}

signal_protocol_address* signal_protocol_address_new(const char* name, int32_t device_id) {
    if (!name)
        return NULL;
    signal_protocol_address* address = malloc(sizeof(signal_protocol_address));
    address->device_id = -1;
    address->name = NULL;
    signal_protocol_address_set_name(address, name);
    signal_protocol_address_set_device_id(address, device_id);
    return address;
}

int aes_cipher(int cipher, size_t key_len, int* algo, int* mode) {
    switch (key_len) {
        case 16:
            *algo = GCRY_CIPHER_AES128;
            break;
        case 24:
            *algo = GCRY_CIPHER_AES192;
            break;
        case 32:
            *algo = GCRY_CIPHER_AES256;
            break;
        default:
            return SG_ERR_UNKNOWN;
    }
    switch (cipher) {
        case SG_CIPHER_AES_CBC_PKCS5:
            *mode = GCRY_CIPHER_MODE_CBC;
            break;
        case SG_CIPHER_AES_CTR_NOPADDING:
            *mode = GCRY_CIPHER_MODE_CTR;
            break;
        default:
            return SG_ERR_UNKNOWN;
    }
    return SG_SUCCESS;
}

void lock_function(void *user_data)
{
    (void) user_data;
}

void unlock_function(void *user_data)
{
    (void) user_data;
}

int cp_randomize(uint8_t *data, size_t len) {
    gcry_randomize(data, len, GCRY_STRONG_RANDOM);
    return SG_SUCCESS;
}

int cp_random_generator(uint8_t *data, size_t len, void *user_data) {
    (void) user_data;

    gcry_randomize(data, len, GCRY_STRONG_RANDOM);
    return SG_SUCCESS;
}

int cp_hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data) {
    (void) user_data;

    gcry_mac_hd_t* ctx = malloc(sizeof(gcry_mac_hd_t));
    if (!ctx) return SG_ERR_NOMEM;

    if (gcry_mac_open(ctx, GCRY_MAC_HMAC_SHA256, 0, 0)) {
        free(ctx);
        return SG_ERR_UNKNOWN;
    }

    if (gcry_mac_setkey(*ctx, key, key_len)) {
        free(ctx);
        return SG_ERR_UNKNOWN;
    }

    *hmac_context = ctx;

    return SG_SUCCESS;
}

int cp_hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data) {
    (void) user_data;

    gcry_mac_hd_t* ctx = hmac_context;

    if (gcry_mac_write(*ctx, data, data_len)) return SG_ERR_UNKNOWN;

    return SG_SUCCESS;
}

int cp_hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data) {
    (void) user_data;

    size_t len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA256);
    uint8_t md[len];
    gcry_mac_hd_t* ctx = hmac_context;

    if (gcry_mac_read(*ctx, md, &len)) return SG_ERR_UNKNOWN;

    signal_buffer *output_buffer = signal_buffer_create(md, len);
    if (!output_buffer) return SG_ERR_NOMEM;

    *output = output_buffer;

    return SG_SUCCESS;
}

void cp_hmac_sha256_cleanup(void *hmac_context, void *user_data) {
    (void) user_data;

    gcry_mac_hd_t* ctx = hmac_context;
    if (ctx) {
        gcry_mac_close(*ctx);
        free(ctx);
    }
}

int cp_sha512_digest_init(void **digest_context, void *user_data) {
    (void) user_data;

    gcry_md_hd_t* ctx = malloc(sizeof(gcry_mac_hd_t));
    if (!ctx) return SG_ERR_NOMEM;

    if (gcry_md_open(ctx, GCRY_MD_SHA512, 0)) {
        free(ctx);
        return SG_ERR_UNKNOWN;
    }

    *digest_context = ctx;

    return SG_SUCCESS;
}

int cp_sha512_digest_update(void *digest_context, const uint8_t *data, size_t data_len, void *user_data) {
    (void) user_data;

    gcry_md_hd_t* ctx = digest_context;

    gcry_md_write(*ctx, data, data_len);

    return SG_SUCCESS;
}

int cp_sha512_digest_final(void *digest_context, signal_buffer **output, void *user_data) {
    (void) user_data;

    size_t len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    gcry_md_hd_t* ctx = digest_context;

    uint8_t* md = gcry_md_read(*ctx, GCRY_MD_SHA512);
    if (!md) return SG_ERR_UNKNOWN;

    gcry_md_reset(*ctx);

    signal_buffer *output_buffer = signal_buffer_create(md, len);
    free(md);
    if (!output_buffer) return SG_ERR_NOMEM;

    *output = output_buffer;

    return SG_SUCCESS;
}

void cp_sha512_digest_cleanup(void *digest_context, void *user_data) {
    (void) user_data;

    gcry_md_hd_t* ctx = digest_context;
    if (ctx) {
        gcry_md_close(*ctx);
        free(ctx);
    }
}

int cp_encrypt(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data) {
    (void) user_data;

    int algo, mode, error_code = SG_ERR_UNKNOWN;
    if (aes_cipher(cipher, key_len, &algo, &mode)) return SG_ERR_INVAL;

    gcry_cipher_hd_t ctx = {0};

    if (gcry_cipher_open(&ctx, algo, mode, 0)) return SG_ERR_NOMEM;

    signal_buffer* padded = 0;
    signal_buffer* out_buf = 0;
    goto no_error;
error:
    gcry_cipher_close(ctx);
    if (padded != 0) {
        signal_buffer_bzero_free(padded);
    }
    if (out_buf != 0) {
        signal_buffer_free(out_buf);
    }
    return error_code;
no_error:

    if (gcry_cipher_setkey(ctx, key, key_len)) goto error;

    uint8_t tag_len = 0, pad_len = 0;
    switch (cipher) {
        case SG_CIPHER_AES_CBC_PKCS5:
            if (gcry_cipher_setiv(ctx, iv, iv_len)) goto error;
            pad_len = 16 - (plaintext_len % 16);
            if (pad_len == 0) pad_len = 16;
            break;
        case SG_CIPHER_AES_CTR_NOPADDING:
            if (gcry_cipher_setctr(ctx, iv, iv_len)) goto error;
            break;
        default:
            return SG_ERR_UNKNOWN;
    }

    size_t padded_len = plaintext_len + pad_len;
    padded = signal_buffer_alloc(padded_len);
    if (padded == 0) {
        error_code = SG_ERR_NOMEM;
        goto error;
    }

    memset(signal_buffer_data(padded) + plaintext_len, pad_len, pad_len);
    memcpy(signal_buffer_data(padded), plaintext, plaintext_len);

    out_buf = signal_buffer_alloc(padded_len + tag_len);
    if (out_buf == 0) {
        error_code = SG_ERR_NOMEM;
        goto error;
    }

    if (gcry_cipher_encrypt(ctx, signal_buffer_data(out_buf), padded_len, signal_buffer_data(padded), padded_len)) goto error;

    if (tag_len > 0) {
        if (gcry_cipher_gettag(ctx, signal_buffer_data(out_buf) + padded_len, tag_len)) goto error;
    }

    *output = out_buf;
    out_buf = 0;

    signal_buffer_bzero_free(padded);
    padded = 0;

    gcry_cipher_close(ctx);
    return SG_SUCCESS;
}

int cp_decrypt(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data) {
    (void) user_data;

    int algo, mode, error_code = SG_ERR_UNKNOWN;
    *output = 0;
    if (aes_cipher(cipher, key_len, &algo, &mode)) return SG_ERR_INVAL;
    if (ciphertext_len == 0) return SG_ERR_INVAL;

    gcry_cipher_hd_t ctx = {0};

    if (gcry_cipher_open(&ctx, algo, mode, 0)) return SG_ERR_NOMEM;

    signal_buffer* out_buf = 0;
    goto no_error;
error:
    gcry_cipher_close(ctx);
    if (out_buf != 0) {
        signal_buffer_bzero_free(out_buf);
    }
    return error_code;
no_error:

    if (gcry_cipher_setkey(ctx, key, key_len)) goto error;

    uint8_t tag_len = 0, pkcs_pad = 0;
    switch (cipher) {
        case SG_CIPHER_AES_CBC_PKCS5:
            if (gcry_cipher_setiv(ctx, iv, iv_len)) goto error;
            pkcs_pad = 1;
            break;
        case SG_CIPHER_AES_CTR_NOPADDING:
            if (gcry_cipher_setctr(ctx, iv, iv_len)) goto error;
            break;
        default:
            goto error;
    }

    size_t padded_len = ciphertext_len - tag_len;
    out_buf = signal_buffer_alloc(padded_len);
    if (out_buf == 0) {
        error_code = SG_ERR_NOMEM;
        goto error;
    }

    if (gcry_cipher_decrypt(ctx, signal_buffer_data(out_buf), signal_buffer_len(out_buf), ciphertext, padded_len)) goto error;

    if (tag_len > 0) {
        if (gcry_cipher_checktag(ctx, ciphertext + padded_len, tag_len)) goto error;
    }

    if (pkcs_pad) {
        uint8_t pad_len = signal_buffer_data(out_buf)[padded_len - 1];
        if (pad_len > 16 || pad_len > padded_len) goto error;
        *output = signal_buffer_create(signal_buffer_data(out_buf), padded_len - pad_len);
        signal_buffer_bzero_free(out_buf);
        out_buf = 0;
    } else {
        *output = out_buf;
        out_buf = 0;
    }

    gcry_cipher_close(ctx);
    return SG_SUCCESS;
}

int iks_get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_local_private_key = mdb_val_str("local_private_key");
    MDB_val k_local_public_key = mdb_val_str("local_public_key");
    MDB_val v_local_private_key, v_local_public_key;

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_local_private_key, &v_local_private_key) &&
        !mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_local_public_key, &v_local_public_key))
    {
        *private_data = signal_buffer_create(v_local_private_key.mv_data, v_local_private_key.mv_size);
        *public_data = signal_buffer_create(v_local_public_key.mv_data, v_local_public_key.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    else
    {
        struct ratchet_identity_key_pair *identity;

        signal_protocol_key_helper_generate_identity_key_pair(
            &identity, omemo->context);
        ec_private_key *private_key = ratchet_identity_key_pair_get_private(identity);
        ec_public_key *public_key = ratchet_identity_key_pair_get_public(identity);

        ec_private_key_serialize(private_data, private_key);
        ec_public_key_serialize(public_data, public_key);

        v_local_private_key.mv_data = signal_buffer_data(*private_data);
        v_local_private_key.mv_size = signal_buffer_len(*private_data);
        v_local_public_key.mv_data = signal_buffer_data(*public_data);
        v_local_public_key.mv_size = signal_buffer_len(*public_data);

        mdb_txn_abort(transaction);
        if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        }

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_local_private_key, &v_local_private_key, MDB_NOOVERWRITE) ||
            mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_local_public_key, &v_local_public_key, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                           weechat_prefix("error"));
            goto cleanup;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };

        *private_data = signal_buffer_create(v_local_private_key.mv_data,
                v_local_private_key.mv_size);
        *public_data = signal_buffer_create(v_local_public_key.mv_data,
                v_local_public_key.mv_size);
        omemo->identity = identity;
    }

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int iks_get_local_registration_id(void *user_data, uint32_t *registration_id)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_local_registration_id = mdb_val_str("local_registration_id");
    MDB_val v_local_registration_id = mdb_val_sizeof(uint32_t);

    // Return the local client's registration ID
    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_local_registration_id,
                 &v_local_registration_id))
    {
        *registration_id = *(uint32_t*)v_local_registration_id.mv_data;

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to read lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    else
    {
        uint32_t generated_id;
        signal_protocol_key_helper_generate_registration_id(
            &generated_id, 0, omemo->context);
        v_local_registration_id.mv_data = &generated_id;

        mdb_txn_abort(transaction);
        if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        }

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_local_registration_id,
                    &v_local_registration_id, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                           weechat_prefix("error"));
            goto cleanup;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };

        *registration_id = generated_id;
    }

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int iks_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_identity_key = {
        .mv_data = NULL,
        .mv_size = strlen("identity_key_") + address->name_len
            + 1 + 10,
    };
    MDB_val v_identity_key = {.mv_data = key_data, .mv_size = key_len};

    k_identity_key.mv_data = malloc(sizeof(char) * (
                                           k_identity_key.mv_size + 1));
    k_identity_key.mv_size =
    snprintf(k_identity_key.mv_data, k_identity_key.mv_size + 1,
             "identity_key_%s_%u", address->name, address->device_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo, &k_identity_key,
                &v_identity_key, 0)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int iks_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_identity_key = {
        .mv_data = NULL,
        .mv_size = strlen("identity_key_") + address->name_len
            + 1 + 10,
    };
    MDB_val v_identity_key = {.mv_data = key_data, .mv_size = key_len};
    int trusted = 1;

    k_identity_key.mv_data = malloc(sizeof(char) * (
                                           k_identity_key.mv_size + 1));
    k_identity_key.mv_size =
    snprintf(k_identity_key.mv_data, k_identity_key.mv_size + 1,
             "identity_key_%s_%u", address->name, address->device_id);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo, &k_identity_key,
                &v_identity_key)) {
      weechat_printf(NULL, "%sxmpp: failed to read lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (v_identity_key.mv_size != key_len ||
        memcmp(v_identity_key.mv_data, key_data, key_len) != 0)
        trusted = 0;

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 1 | trusted;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

void iks_destroy_func(void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    (void) omemo;
    // Function called to perform cleanup when the data store context is being destroyed
}

int pks_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_pre_key = {.mv_data = record, .mv_size = record_len};

    k_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_pre_key.mv_size + 1));
    k_pre_key.mv_size =
    snprintf(k_pre_key.mv_data, k_pre_key.mv_size + 1,
             "pre_key_%-10u", pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo, &k_pre_key,
                &v_pre_key, 0)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int pks_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_pre_key;

    k_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_pre_key.mv_size + 1));
    k_pre_key.mv_size =
    snprintf(k_pre_key.mv_data, k_pre_key.mv_size + 1,
             "pre_key_%-10u", pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo, &k_pre_key,
                &v_pre_key)) {
        weechat_printf(NULL, "%sxmpp: failed to read lmdb value",
                       weechat_prefix("error"));
        mdb_txn_abort(transaction);
        goto cleanup;
    };

    mdb_txn_abort(transaction);

    return 1;
cleanup:
    mdb_txn_abort(transaction);
    return 0;
}

uint32_t pks_get_count(struct t_omemo *omemo, int increment)
{
    uint32_t count = PRE_KEY_START;
    MDB_txn *transaction = NULL;
    MDB_val k_pre_key_idx = {
        .mv_data = "pre_key_idx",
        .mv_size = strlen("pre_key_idx"),
    };
    MDB_val v_pre_key_idx = mdb_val_intptr(&count);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_pre_key_idx, &v_pre_key_idx))
    {
        if (increment)
            count += PRE_KEY_COUNT;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo,
                &k_pre_key_idx, &v_pre_key_idx, 0))
    {
        weechat_printf(NULL, "%sxmpp: failed to read lmdb value",
                       weechat_prefix("error"));
        goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return count;
cleanup:
    mdb_txn_abort(transaction);
    return 0;
}

int pks_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_pre_key;

    k_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_pre_key.mv_size + 1));
    k_pre_key.mv_size =
    snprintf(k_pre_key.mv_data, k_pre_key.mv_size + 1,
             "pre_key_%-10u", pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_pre_key, &v_pre_key))
    {
        *record = signal_buffer_create(v_pre_key.mv_data, v_pre_key.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    else
    {
        mdb_txn_abort(transaction);

        signal_protocol_key_helper_pre_key_list_node *pre_keys_list;
        session_pre_key *pre_key = NULL;

        for (signal_protocol_key_helper_generate_pre_keys(&pre_keys_list,
                    pks_get_count(omemo, 1), PRE_KEY_COUNT,
                    omemo->context); pre_keys_list;
             pre_keys_list = signal_protocol_key_helper_key_list_next(pre_keys_list))
        {
            pre_key = signal_protocol_key_helper_key_list_element(pre_keys_list);
            uint32_t id = session_pre_key_get_id(pre_key);
            session_pre_key_serialize(record, pre_key);
            pks_store_pre_key(id, signal_buffer_data(*record),
                    signal_buffer_len(*record), user_data);
        }
        signal_protocol_key_helper_key_list_free(pre_keys_list);
    }

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int pks_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_pre_key;

    k_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_pre_key.mv_size + 1));
    k_pre_key.mv_size =
    snprintf(k_pre_key.mv_data, k_pre_key.mv_size + 1,
             "pre_key_%-10u", pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_del(transaction, omemo->db->dbi_omemo, &k_pre_key,
                &v_pre_key)) {
      weechat_printf(NULL, "%sxmpp: failed to erase lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

void pks_destroy_func(void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    (void) omemo;
    // Function called to perform cleanup when the data store context is being destroyed
}

int spks_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_signed_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("signed_pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_signed_pre_key;

    k_signed_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_signed_pre_key.mv_size + 1));
    k_signed_pre_key.mv_size =
    snprintf(k_signed_pre_key.mv_data, k_signed_pre_key.mv_size + 1,
             "signed_pre_key_%-10u", signed_pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_signed_pre_key, &v_signed_pre_key))
    {
        *record = signal_buffer_create(v_signed_pre_key.mv_data, v_signed_pre_key.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    else
    {
        session_signed_pre_key *signed_pre_key = NULL;
        signal_buffer *serialized_key = NULL;

        signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, omemo->identity, signed_pre_key_id, time(NULL), omemo->context);
        session_signed_pre_key_serialize(&serialized_key, signed_pre_key);

        v_signed_pre_key.mv_data = signal_buffer_data(serialized_key);
        v_signed_pre_key.mv_size = signal_buffer_len(serialized_key);

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_signed_pre_key, &v_signed_pre_key, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to read lmdb value",
                           weechat_prefix("error"));
            goto cleanup;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };

        *record = serialized_key;
    }

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int spks_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_signed_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("signed_pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_signed_pre_key = {.mv_data = record, .mv_size = record_len};

    k_signed_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_signed_pre_key.mv_size + 1));
    k_signed_pre_key.mv_size =
    snprintf(k_signed_pre_key.mv_data, k_signed_pre_key.mv_size + 1,
             "signed_pre_key_%-10u", signed_pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo, &k_signed_pre_key,
                &v_signed_pre_key, 0)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int spks_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_signed_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("signed_pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_signed_pre_key;

    k_signed_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_signed_pre_key.mv_size + 1));
    k_signed_pre_key.mv_size =
    snprintf(k_signed_pre_key.mv_data, k_signed_pre_key.mv_size + 1,
             "signed_pre_key_%-10u", signed_pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo, &k_signed_pre_key,
                &v_signed_pre_key)) {
        mdb_txn_abort(transaction);
        goto cleanup;
    };

    mdb_txn_abort(transaction);

    return 1;
cleanup:
    mdb_txn_abort(transaction);
    return 0;
}

int spks_remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_signed_pre_key = {
        .mv_data = NULL,
        .mv_size = strlen("signed_pre_key_") + 10, // strlen(UINT32_MAX)
    };
    MDB_val v_signed_pre_key;

    k_signed_pre_key.mv_data = malloc(sizeof(char) * (
                                           k_signed_pre_key.mv_size + 1));
    k_signed_pre_key.mv_size =
    snprintf(k_signed_pre_key.mv_data, k_signed_pre_key.mv_size + 1,
             "signed_pre_key_%-10u", signed_pre_key_id);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_del(transaction, omemo->db->dbi_omemo, &k_signed_pre_key,
                &v_signed_pre_key)) {
      weechat_printf(NULL, "%sxmpp: failed to erase lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

void spks_destroy_func(void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    (void) omemo;
    // Function called to perform cleanup when the data store context is being destroyed
}

int ss_load_session_func(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_session = {
        .mv_data = NULL,
        .mv_size = strlen("session_") + 10 + //strlen(address->device_id) +
             1 + strlen(address->name),
    };
    MDB_val v_session;
    MDB_val k_user = {
        .mv_data = NULL,
        .mv_size = strlen("user_") + 10 + //strlen(address->device_id) +
             1 + strlen(address->name),
    };
    MDB_val v_user; (void) v_user; (void) user_record;

    k_session.mv_data = malloc(sizeof(char) * (k_session.mv_size + 1));
    k_session.mv_size =
    snprintf(k_session.mv_data, k_session.mv_size + 1,
             "session_%u_%s", address->device_id, address->name);
    k_user.mv_data = malloc(sizeof(char) * (k_user.mv_size + 1));
    k_user.mv_size =
    snprintf(k_user.mv_data, k_user.mv_size + 1,
             "user_%u_%s", address->device_id, address->name);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_session, &v_session)/* ||
        mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_user, &v_user)*/)
    {
        mdb_txn_abort(transaction);
        return 0;
    }

    *record = signal_buffer_create(v_session.mv_data, v_session.mv_size);
  //*user_record = signal_buffer_create(v_user.mv_data, v_user.mv_size);

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return 1;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int ss_get_sub_device_sessions_func(signal_int_list **sessions, const char *name, size_t name_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_device_ids = {
        .mv_data = NULL,
        .mv_size = strlen("device_ids_") + name_len,
    };
    MDB_val v_device_ids;

    k_device_ids.mv_data = malloc(sizeof(char) * (
                                           k_device_ids.mv_size + 1));
    snprintf(k_device_ids.mv_data, k_device_ids.mv_size + 1,
             "device_ids_%s", name);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_device_ids, &v_device_ids))
    {
        char **argv;
        int argc, i;
        signal_int_list *list = signal_int_list_alloc();

        if (!list) {
            goto cleanup;
        }

        argv = weechat_string_split(v_device_ids.mv_data, " ", NULL, 0, 0, &argc);
        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };

        for (i = 0; i < argc; i++)
        {
            char* device_id = argv[i];

            signal_int_list_push_back(list, strtol(device_id, NULL, 10));
        }

        weechat_string_free_split(argv);

        *sessions = list;
        return argc;
    }
    else
    {
        mdb_txn_abort(transaction);
        return 0;
    }
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int ss_store_session_func(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_session = {
        .mv_data = NULL,
        .mv_size = strlen("session_") + 10 + //strlen(address->device_id) +
             1 + strlen(address->name),
    };
    MDB_val v_session = {.mv_data = record, .mv_size = record_len};
    MDB_val k_user = {
        .mv_data = NULL,
        .mv_size = strlen("user_") + 10 + //strlen(address->device_id) +
             1 + strlen(address->name),
    };
    MDB_val v_user = {.mv_data = user_record, .mv_size = user_record_len}; (void) v_user;

    k_session.mv_data = malloc(sizeof(char) * (
                                           k_session.mv_size + 1));
    k_session.mv_size =
    snprintf(k_session.mv_data, k_session.mv_size + 1,
             "session_%u_%s", address->device_id, address->name);
    k_user.mv_data = malloc(sizeof(char) * (
                                           k_user.mv_size + 1));
    k_user.mv_size =
    snprintf(k_user.mv_data, k_user.mv_size + 1,
             "user_%u_%s", address->device_id, address->name);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo,
                &k_session, &v_session, 0)/* ||
        mdb_put(transaction, omemo->db->dbi_omemo,
                &k_user, &v_user, 0)*/) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int ss_contains_session_func(const signal_protocol_address *address, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_session = {
        .mv_data = NULL,
        .mv_size = strlen("session_") + 10 + //strlen(address->device_id) +
             1 + strlen(address->name),
    };
    MDB_val v_session;

    k_session.mv_data = malloc(sizeof(char) * (
                                           k_session.mv_size + 1));
    k_session.mv_size =
        snprintf(k_session.mv_data, k_session.mv_size + 1,
                 "session_%u_%s", address->device_id, address->name);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return 0;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo, &k_session, &v_session)) {
        mdb_txn_abort(transaction);
        return 0;
    };

    mdb_txn_abort(transaction);
    return 1;
}

int ss_delete_session_func(const signal_protocol_address *address, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_session = {
        .mv_data = NULL,
        .mv_size = strlen("session_") + 10 + //strlen(address->device_id) +
             1 + strlen(address->name),
    };
    MDB_val v_session;

    k_session.mv_data = malloc(sizeof(char) * (
                                           k_session.mv_size + 1));
    k_session.mv_size =
        snprintf(k_session.mv_data, k_session.mv_size + 1,
                 "session_%u_%s", address->device_id, address->name);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_del(transaction, omemo->db->dbi_omemo, &k_session, &v_session)) {
        weechat_printf(NULL, "%sxmpp: failed to erase lmdb value",
                       weechat_prefix("error"));
        goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return 1;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int ss_delete_all_sessions_func(const char *name, size_t name_len, void *user_data)
{
    signal_int_list *sessions;
    ss_get_sub_device_sessions_func(&sessions, name, name_len, user_data);

    int n = signal_int_list_size(sessions);
    for (int i = 0; i < n; i++)
    {
        signal_protocol_address address = {.name = name, .name_len = name_len,
            .device_id = signal_int_list_at(sessions, i)};
        ss_delete_session_func(&address, user_data);
    }
    signal_int_list_free(sessions);
    return -1;
}

void ss_destroy_func(void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    (void) omemo;
    // Function called to perform cleanup when the data store context is being destroyed
}

int sks_store_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    char *device_list = NULL;
    MDB_txn *transaction = NULL;
    MDB_val k_sender_key = {
        .mv_data = NULL,
        .mv_size = strlen("sender_key_") + strlen(sender_key_name->group_id) +
             1 + 10 + //strlen(sender_key_name->sender.device_id) +
             1 + strlen(sender_key_name->sender.name),
    };
    MDB_val v_sender_key = {.mv_data = record, .mv_size = record_len};
    MDB_val k_user = {
        .mv_data = NULL,
        .mv_size = strlen("user_") + strlen(sender_key_name->group_id) +
             1 + 10 + //strlen(sender_key_name->sender.device_id) +
             1 + strlen(sender_key_name->sender.name),
    };
    MDB_val v_user = {.mv_data = user_record, .mv_size = user_record_len}; (void) v_user;
    MDB_val k_device_ids = {
        .mv_data = NULL,
        .mv_size = strlen("device_ids_") + strlen(sender_key_name->sender.name),
    };
    MDB_val v_device_ids;

    k_sender_key.mv_data = malloc(sizeof(char) * (
                                           k_sender_key.mv_size + 1));
    k_sender_key.mv_size =
    snprintf(k_sender_key.mv_data, k_sender_key.mv_size + 1,
             "sender_key_%s_%u_%s", sender_key_name->group_id,
             sender_key_name->sender.device_id,
             sender_key_name->sender.name);
    k_user.mv_data = malloc(sizeof(char) * (
                                           k_user.mv_size + 1));
    k_user.mv_size =
    snprintf(k_user.mv_data, k_user.mv_size + 1,
             "user_%s_%u_%s", sender_key_name->group_id,
             sender_key_name->sender.device_id,
             sender_key_name->sender.name);
    k_device_ids.mv_data = malloc(sizeof(char) * (
                                           k_device_ids.mv_size + 1));
    snprintf(k_device_ids.mv_data, k_device_ids.mv_size + 1,
             "device_ids_%s", sender_key_name->sender.name);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (!mdb_get(transaction, omemo->db->dbi_omemo,
                 &k_device_ids, &v_device_ids))
    {
        char **argv;
        int argc, i;

        argv = weechat_string_split(v_device_ids.mv_data, " ", NULL, 0, 0, &argc);
        for (i = 0; i < argc; i++)
        {
            char* device_id = argv[i];
            if (strtol(device_id, NULL, 10) == sender_key_name->sender.device_id) break;
        }

        weechat_string_free_split(argv);

        if (i == argc)
        {
            size_t device_list_len = strlen(v_device_ids.mv_data) + 1 + 10 + 1;
            device_list = malloc(sizeof(char) * device_list_len);
            snprintf(device_list, device_list_len, "%s %u",
                     (char*)v_device_ids.mv_data, sender_key_name->sender.device_id);
            v_device_ids.mv_data = device_list;
            v_device_ids.mv_size = strlen(device_list) + 1;
        }
    }
    else
    {
        device_list = malloc(sizeof(char) * (10 + 1));
        snprintf(device_list, 10 + 1, "%u", sender_key_name->sender.device_id);
        v_device_ids.mv_data = device_list;
        v_device_ids.mv_size = strlen(device_list) + 1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo,
                &k_sender_key, &v_sender_key, 0)/* ||
        mdb_put(transaction, omemo->db->dbi_omemo,
                &k_user, &v_user, 0)*/ ||
        mdb_put(transaction, omemo->db->dbi_omemo,
                &k_device_ids, &v_device_ids, 0)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };
    free(device_list);

    return 0;
cleanup:
    free(device_list);
    mdb_txn_abort(transaction);
    return -1;
}

int sks_load_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction = NULL;
    MDB_val k_sender_key = {
        .mv_data = NULL,
        .mv_size = strlen("sender_key_") + strlen(sender_key_name->group_id) +
             1 + 10 + //strlen(sender_key_name->sender.device_id) +
             1 + strlen(sender_key_name->sender.name),
    };
    MDB_val v_sender_key;
    MDB_val k_user = {
        .mv_data = NULL,
        .mv_size = strlen("user_") + strlen(sender_key_name->group_id) +
             1 + 10 + //strlen(sender_key_name->sender.device_id) +
             1 + strlen(sender_key_name->sender.name),
    };
    MDB_val v_user; (void) v_user; (void) user_record;

    k_sender_key.mv_data = malloc(sizeof(char) * (
                                           k_sender_key.mv_size + 1));
    k_sender_key.mv_size =
    snprintf(k_sender_key.mv_data, k_sender_key.mv_size + 1,
             "sender_key_%s_%u_%s", sender_key_name->group_id,
             sender_key_name->sender.device_id,
             sender_key_name->sender.name);
    k_user.mv_data = malloc(sizeof(char) * (
                                           k_user.mv_size + 1));
    k_user.mv_size =
    snprintf(k_user.mv_data, k_user.mv_size + 1,
             "user_%s_%u_%s", sender_key_name->group_id,
             sender_key_name->sender.device_id,
             sender_key_name->sender.name);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_sender_key, &v_sender_key)/* &&
        mdb_get(transaction, omemo->db->dbi_omemo,
                &k_user, &v_user)*/)
    {
        *record = signal_buffer_create(v_sender_key.mv_data, v_sender_key.mv_size);
      //*user_record = signal_buffer_create(v_user.mv_data, v_user.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    else
    {
        goto cleanup;
    }

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

void sks_destroy_func(void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    (void) omemo;
    // Function called to perform cleanup when the data store context is being destroyed
}

int dls_store_devicelist(const char *jid, signal_int_list *devicelist, struct t_omemo *omemo)
{
    MDB_txn *transaction = NULL;
    MDB_val k_devicelist = {
        .mv_data = NULL,
        .mv_size = strlen("devicelist_") + strlen(jid),
    };
    MDB_val v_devicelist;

    k_devicelist.mv_data = malloc(sizeof(char) * (
                                           k_devicelist.mv_size + 1));
    k_devicelist.mv_size =
    snprintf(k_devicelist.mv_data, k_devicelist.mv_size + 1,
             "devicelist_%s", jid);
    char *devices[128] = {0};
    for (size_t i = 0; i < signal_int_list_size(devicelist); i++)
    {
        int device = signal_int_list_at(devicelist, i);
        devices[i] = malloc(sizeof(*devices) * (10 + 1));
        devices[i+1] = NULL;
        snprintf(devices[i], 10 + 1, "%u", device);
    }
    v_devicelist.mv_data = weechat_string_build_with_split_string(
            (const char **)devices, ";");
    v_devicelist.mv_size = strlen(v_devicelist.mv_data);
    for (char **device = (char **)devices; *device; device++) free(*device);

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo, &k_devicelist,
                &v_devicelist, 0)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      goto cleanup;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int dls_load_devicelist(signal_int_list **devicelist, const char *jid, struct t_omemo *omemo)
{
    MDB_txn *transaction = NULL;
    MDB_val k_devicelist = {
        .mv_data = NULL,
        .mv_size = strlen("devicelist_") + strlen(jid),
    };
    MDB_val v_devicelist;

    k_devicelist.mv_data = malloc(sizeof(char) * (
                                           k_devicelist.mv_size + 1));
    k_devicelist.mv_size =
    snprintf(k_devicelist.mv_data, k_devicelist.mv_size + 1,
             "devicelist_%s", jid);

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_devicelist, &v_devicelist))
    {
        goto cleanup;
    }

    *devicelist = signal_int_list_alloc();
    int devices_len = 0;
    char **devices = weechat_string_split(v_devicelist.mv_data, ";", NULL, 0, 0, &devices_len);
    for (int i = 0; i < devices_len; i++)
    {
        char* device_id = devices[i];
        signal_int_list_push_back(*devicelist, strtol(device_id, NULL, 10));
    }
    weechat_string_free_split(devices);

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int bks_store_bundle(signal_protocol_address *address,
        struct t_pre_key **pre_keys, struct t_pre_key **signed_pre_keys,
        const char *signature, const char *identity_key, struct t_omemo *omemo)
{
    size_t n_pre_keys = -1;
    while (pre_keys[++n_pre_keys] != NULL);
    char **pre_key_buffers = malloc(sizeof(char*) * (n_pre_keys + 1));
    for (size_t i = 0; i < n_pre_keys; i++)
    {
        struct t_pre_key *pre_key = pre_keys[i];
        size_t keylen = 10 + strlen(pre_key->public_key) + 1;
        pre_key_buffers[i] = malloc(sizeof(char) * keylen);
        pre_key_buffers[i+1] = NULL;
        snprintf(pre_key_buffers[i], keylen,
             "%s.%s", pre_key->id, pre_key->public_key);
    }

    size_t n_signed_pre_keys = -1;
    while (signed_pre_keys[++n_signed_pre_keys] != NULL);
    char **signed_pre_key_buffers = malloc(sizeof(char*) * (n_signed_pre_keys + 1));
    for (size_t i = 0; i < n_signed_pre_keys; i++)
    {
        struct t_pre_key *signed_pre_key = signed_pre_keys[i];
        size_t keylen = 10 + 1 + strlen(signed_pre_key->public_key);
        signed_pre_key_buffers[i] = malloc(sizeof(char) * (keylen + 1));
        signed_pre_key_buffers[i+1] = NULL;
        snprintf(signed_pre_key_buffers[i], keylen + 1,
             "%s.%s", signed_pre_key->id, signed_pre_key->public_key);

        int ret;
        uint8_t *signing_key_buf;
        size_t signing_key_len = base64_decode(identity_key,
                strlen(identity_key), &signing_key_buf);
        ec_public_key *signing_key;
        if ((ret = curve_decode_point(&signing_key, signing_key_buf,
                        signing_key_len, omemo->context))) {
            weechat_printf(NULL, "%sxmpp: failed to decode ED25519 prekey",
                           weechat_prefix("error"));
            goto cleanup;
        };
        uint8_t *signed_key_buf;
        size_t signed_key_len = base64_decode(signed_pre_key->public_key,
                strlen(signed_pre_key->public_key), &signed_key_buf);
        uint8_t *signature_buf;
        size_t signature_len = base64_decode(signature,
                strlen(signature), &signature_buf);
        int valid = curve_verify_signature(signing_key,
                signed_key_buf, signed_key_len,
                signature_buf, signature_len);
        if (valid <= 0) {
            weechat_printf(NULL, "%somemo: failed to validate ED25519 signature for %s:%u",
                           weechat_prefix("error"), address->name, address->device_id);
        }
    }

    MDB_txn *transaction = NULL;
    const char *jid = address->name;
    uint32_t device_id = address->device_id;
    size_t keylen = strlen("bundle_??_") + strlen(jid) + 1 + 10 + 1;
    MDB_val k_bundle_pk = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_pk.mv_size = snprintf(k_bundle_pk.mv_data, keylen,
             "bundle_pk_%s_%u", jid, device_id);
    MDB_val k_bundle_sk = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_sk.mv_size = snprintf(k_bundle_sk.mv_data, keylen,
             "bundle_sk_%s_%u", jid, device_id);
    MDB_val k_bundle_sg = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_sg.mv_size = snprintf(k_bundle_sg.mv_data, keylen,
             "bundle_sg_%s_%u", jid, device_id);
    MDB_val k_bundle_ik = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_ik.mv_size = snprintf(k_bundle_ik.mv_data, keylen,
             "bundle_ik_%s_%u", jid, device_id);

    MDB_val v_bundle_pk = {
        .mv_data = weechat_string_build_with_split_string(
            (const char **)pre_key_buffers, ";"),
        .mv_size = 0,
    };
    v_bundle_pk.mv_size = strlen(v_bundle_pk.mv_data) + 1;
    MDB_val v_bundle_sk = {
        .mv_data = weechat_string_build_with_split_string(
            (const char **)signed_pre_key_buffers, ";"),
        .mv_size = 0,
    };
    v_bundle_sk.mv_size = strlen(v_bundle_sk.mv_data) + 1;
    MDB_val v_bundle_sg = {
        .mv_data = (char*)signature,
        .mv_size = strlen(signature),
    };
    MDB_val v_bundle_ik = {
        .mv_data = (char*)identity_key,
        .mv_size = strlen(identity_key),
    };

    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    int ret;
    if ((ret = mdb_put(transaction, omemo->db->dbi_omemo, &k_bundle_pk,
                 &v_bundle_pk, 0)) ||
        (ret = mdb_put(transaction, omemo->db->dbi_omemo, &k_bundle_sk,
                 &v_bundle_sk, 0)) ||
        (ret = mdb_put(transaction, omemo->db->dbi_omemo, &k_bundle_sg,
                 &v_bundle_sg, 0)) ||
        (ret = mdb_put(transaction, omemo->db->dbi_omemo, &k_bundle_ik,
                 &v_bundle_ik, 0))) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value '%s'@%u: %s",
                     weechat_prefix("error"), v_bundle_pk.mv_data, v_bundle_pk.mv_size, mdb_strerror(ret));
      goto cleanup;
    };

    if ((ret = mdb_txn_commit(transaction))) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      goto cleanup;
    };

    return 0;
cleanup:
    mdb_txn_abort(transaction);
    return -1;
}

int bks_load_bundle(session_pre_key_bundle **bundle, signal_protocol_address *address, struct t_omemo *omemo)
{
    MDB_txn *transaction = NULL;
    const char *jid = address->name;
    uint32_t device_id = address->device_id;
    size_t keylen = strlen("bundle_??_") + address->name_len + 1 + 10 + 1;
    MDB_val k_bundle_pk = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_pk.mv_size = snprintf(k_bundle_pk.mv_data, keylen,
             "bundle_pk_%s_%u", jid, device_id);
    MDB_val k_bundle_sk = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_sk.mv_size = snprintf(k_bundle_sk.mv_data, keylen,
             "bundle_sk_%s_%u", jid, device_id);
    MDB_val k_bundle_sg = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_sg.mv_size = snprintf(k_bundle_sg.mv_data, keylen,
             "bundle_sg_%s_%u", jid, device_id);
    MDB_val k_bundle_ik = {
        .mv_data = malloc(sizeof(char) * (keylen + 1)),
        .mv_size = 0,
    };
    k_bundle_ik.mv_size = snprintf(k_bundle_ik.mv_data, keylen,
             "bundle_ik_%s_%u", jid, device_id);

    MDB_val v_bundle_pk;
    MDB_val v_bundle_sk;
    MDB_val v_bundle_sg;
    MDB_val v_bundle_ik;

    int ret;
    if ((ret = mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction))) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if ((ret = mdb_get(transaction, omemo->db->dbi_omemo,
                       &k_bundle_pk, &v_bundle_pk)) ||
        (ret = mdb_get(transaction, omemo->db->dbi_omemo,
                       &k_bundle_sk, &v_bundle_sk)) ||
        (ret = mdb_get(transaction, omemo->db->dbi_omemo,
                       &k_bundle_sg, &v_bundle_sg)) ||
        (ret = mdb_get(transaction, omemo->db->dbi_omemo,
                       &k_bundle_ik, &v_bundle_ik)))
    {
        goto cleanup;
    }

    int bundle_pk_len = 0;
    char **bundle_pks = weechat_string_split(v_bundle_pk.mv_data, ";", NULL, 0, 0, &bundle_pk_len);
    uint32_t pre_key_id = 0;
    ec_public_key *pre_key;
    //for (int i = 0; i < bundle_pk_len; i++)
    {
        int i = rand() % bundle_pk_len;
        char *bundle_pk = bundle_pks[i];
        pre_key_id = strtol(bundle_pk, NULL, 10);
        char *key_data = memchr(bundle_pk, '.', 10 + 1) + 1;
        uint8_t *key_buf;
        size_t key_len = base64_decode(key_data, strlen(key_data), &key_buf);
        if ((ret = curve_decode_point(&pre_key, key_buf, key_len, omemo->context))) {
            weechat_printf(NULL, "%sxmpp: failed to decode ED25519 prekey",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    int bundle_sk_len;
    char **bundle_sks = weechat_string_split(v_bundle_sk.mv_data, ";", NULL, 0, 0, &bundle_sk_len);
    uint32_t signed_pre_key_id;
    ec_public_key *signed_pre_key;
    //for (int i = 0; i < bundle_sk_len; i++)
    {
        int i = rand() % bundle_sk_len;
        char *bundle_sk = bundle_sks[i];
        signed_pre_key_id = strtol(bundle_sk, NULL, 10);
        char *key_data = memchr(bundle_sk, '.', 10 + 1) + 1;
        uint8_t *key_buf;
        size_t key_len = base64_decode(key_data, strlen(key_data), &key_buf);
        if ((ret = curve_decode_point(&signed_pre_key, key_buf, key_len, omemo->context))) {
            weechat_printf(NULL, "%sxmpp: failed to decode ED25519 signed prekey",
                           weechat_prefix("error"));
            goto cleanup;
        };
    }
    uint8_t *sig_buf;
    size_t sig_len = base64_decode(v_bundle_sg.mv_data, v_bundle_sg.mv_size, &sig_buf);
    signal_buffer *signature = signal_buffer_create(sig_buf, sig_len);
    ec_public_key *identity_key;
    uint8_t *key_buf;
    size_t key_len = base64_decode(v_bundle_ik.mv_data, v_bundle_ik.mv_size, &key_buf);
    if ((ret = curve_decode_point(&identity_key, key_buf, key_len, omemo->context))) {
        weechat_printf(NULL, "%sxmpp: failed to decode ED25519 identity key",
                       weechat_prefix("error"));
        goto cleanup;
    };

    if ((ret = session_pre_key_bundle_create(bundle, device_id, device_id/*?*/, pre_key_id, pre_key, signed_pre_key_id, signed_pre_key, signal_buffer_data(signature), signal_buffer_len(signature), identity_key))) {
        weechat_printf(NULL, "%sxmpp: failed to create OMEMO prekey bundle",
                       weechat_prefix("error"));
        goto cleanup;
    };

    if ((ret = mdb_txn_commit(transaction))) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        goto cleanup;
    };

    return 0;
cleanup:
    /*
    void session_pre_key_bundle_destroy(signal_type_base *type);
     */
    mdb_txn_abort(transaction);
    return -1;
}

void omemo__log_emit_weechat(int level, const char *message, size_t len, void *user_data)
{
    struct t_gui_buffer *buffer = (struct t_gui_buffer*)user_data;

    static const char *log_level_name[5] = {"error", "warn", "notice", "info", "debug"};

    const char *tags = level < SG_LOG_DEBUG ? "no_log" : NULL;

    (void)buffer;
    weechat_printf_date_tags(
        NULL, 0, tags,
        _("%somemo (%s): %.*s"),
        weechat_prefix("network"),
        log_level_name[level], len, message);
}

xmpp_stanza_t *omemo__get_bundle(xmpp_ctx_t *context, char *from, char *to,
                                 struct t_omemo *omemo)
{
    xmpp_stanza_t **children = malloc(sizeof(*children) * (100 + 1));
    xmpp_stanza_t *parent = NULL;
    signal_buffer *record = NULL;
    ec_key_pair *keypair = NULL;
    ec_public_key *public_key = NULL;

    int num_keys = 0;
    for (uint32_t id = PRE_KEY_START;
            id < INT_MAX && num_keys < 100; id++)
    {
        if (pks_load_pre_key(&record, id, omemo) != 0) continue;
        else num_keys++;
        session_pre_key *pre_key = NULL;
        session_pre_key_deserialize(&pre_key, signal_buffer_data(record),
                signal_buffer_len(record), omemo->context);
        if (pre_key == 0) (*((int*)0))++;
        signal_buffer_free(record);
        keypair = session_pre_key_get_key_pair(pre_key);
        public_key = ec_key_pair_get_public(keypair);
        ec_public_key_serialize(&record, public_key);
        char *data = NULL;
        base64_encode(signal_buffer_data(record),
                signal_buffer_len(record), &data);
        signal_buffer_free(record);
        if (pre_key) session_pre_key_destroy((signal_type_base*)pre_key);
      //SIGNAL_UNREF(pre_key);
        char *id_str = malloc(sizeof(char) * (10 + 1));
        snprintf(id_str, 10+1, "%u", id);
        children[num_keys-1] = stanza__iq_pubsub_publish_item_bundle_prekeys_preKeyPublic(
                context, NULL, NULL, with_free(id_str));
        stanza__set_text(context, children[num_keys-1], with_free(data));
    }
    children[100] = NULL;

    children[3] = stanza__iq_pubsub_publish_item_bundle_prekeys(
            context, NULL, children);
    children[4] = NULL;

    spks_load_signed_pre_key(&record, 1, omemo);
    session_signed_pre_key *signed_pre_key;
    session_signed_pre_key_deserialize(&signed_pre_key,
            signal_buffer_data(record), signal_buffer_len(record),
            omemo->context);
    signal_buffer_free(record);
    uint32_t signed_pre_key_id = session_signed_pre_key_get_id(signed_pre_key);
    keypair = session_signed_pre_key_get_key_pair(signed_pre_key);
    public_key = ec_key_pair_get_public(keypair);
    ec_public_key_serialize(&record, public_key);
    char *signed_pre_key_public = NULL;
    base64_encode(signal_buffer_data(record), signal_buffer_len(record),
            &signed_pre_key_public);
    signal_buffer_free(record);
    char *signed_pre_key_id_str = malloc(sizeof(char) * (10 + 1));
    snprintf(signed_pre_key_id_str, 10+1, "%u", signed_pre_key_id);
    children[0] = stanza__iq_pubsub_publish_item_bundle_signedPreKeyPublic(
            context, NULL, NULL, with_free(signed_pre_key_id_str));
    stanza__set_text(context, children[0], with_free(signed_pre_key_public));

    const uint8_t *keysig = session_signed_pre_key_get_signature(signed_pre_key);
    size_t keysig_len = session_signed_pre_key_get_signature_len(signed_pre_key);
    char *signed_pre_key_signature = NULL;
    base64_encode(keysig, keysig_len, &signed_pre_key_signature);
    session_pre_key_destroy((signal_type_base*)signed_pre_key);
    children[1] = stanza__iq_pubsub_publish_item_bundle_signedPreKeySignature(
            context, NULL, NULL);
    stanza__set_text(context, children[1], with_free(signed_pre_key_signature));

    iks_get_identity_key_pair(&record, (signal_buffer**)&signed_pre_key, omemo);
    char *identity_key = NULL;
    base64_encode(signal_buffer_data(record), signal_buffer_len(record),
            &identity_key);
    signal_buffer_free(record);
    children[2] = stanza__iq_pubsub_publish_item_bundle_identityKey(
            context, NULL, NULL);
    stanza__set_text(context, children[2], with_free(identity_key));

    children[0] = stanza__iq_pubsub_publish_item_bundle(
            context, NULL, children, with_noop("eu.siacs.conversations.axolotl"));
    children[1] = NULL;

    children[0] = stanza__iq_pubsub_publish_item(
            context, NULL, children, NULL);

    size_t bundle_node_len = strlen("eu.siacs.conversations.axolotl.bundles:") + 10;
    char *bundle_node = malloc(sizeof(char) * (bundle_node_len + 1));
    snprintf(bundle_node, bundle_node_len+1,
            "eu.siacs.conversations.axolotl.bundles:%u", omemo->device_id);
    children[0] = stanza__iq_pubsub_publish(
            context, NULL, children, with_free(bundle_node));

    omemo__handle_bundle(omemo, from, omemo->device_id, children[0]);

    children[0] = stanza__iq_pubsub(
            context, NULL, children, with_noop("http://jabber.org/protocol/pubsub"));

    parent = stanza__iq(
            context, NULL, children, NULL, "announce2", from, to, "set");
    free(children);

    return parent;
}

void omemo__init(struct t_gui_buffer *buffer, struct t_omemo **omemo,
                 const char *account_name)
{
    struct t_omemo *new_omemo;

    gcry_check_version(NULL);

    new_omemo = calloc(1, sizeof(**omemo));

    new_omemo->db = malloc(sizeof(struct t_omemo_db));

    signal_context_create(&new_omemo->context, buffer);
    signal_context_set_log_function(new_omemo->context, &omemo__log_emit_weechat);

    int ret;
    mdb_env_create(&new_omemo->db->env);
    mdb_env_set_maxdbs(new_omemo->db->env, 50);
    mdb_env_set_mapsize(new_omemo->db->env, (size_t)1048576 * 8000); // 8000MB map for valgrind
    new_omemo->db_path = weechat_string_eval_expression(
            "${weechat_data_dir}/xmpp.omemo.db", NULL, NULL, NULL);
    if ((ret = mdb_env_open(new_omemo->db->env, new_omemo->db_path, MDB_NOSUBDIR, 0664)) != 0)
    {
        weechat_printf(NULL, "%sxmpp: failed to open environment file. %s",
                       weechat_prefix("error"), mdb_strerror(ret));
        return;
    }

    MDB_txn *parentTransaction = NULL;
    MDB_txn *transaction = NULL;
    if (mdb_txn_begin(new_omemo->db->env, parentTransaction, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return;
    }

    size_t db_name_len = strlen("omemo_") + strlen(account_name);
    char *db_name = malloc(sizeof(char) * (db_name_len + 1));
    snprintf(db_name, db_name_len+1, "omemo_%s", account_name);
    if (mdb_dbi_open(transaction, db_name, MDB_CREATE, &new_omemo->db->dbi_omemo)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb database",
                       weechat_prefix("error"));
        return;
    }

    if (mdb_txn_commit(transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                       weechat_prefix("error"));
        return;
    };

    struct signal_crypto_provider crypto_provider = {
        .random_func = &cp_random_generator,
        .hmac_sha256_init_func = &cp_hmac_sha256_init,
        .hmac_sha256_update_func = &cp_hmac_sha256_update,
        .hmac_sha256_final_func = &cp_hmac_sha256_final,
        .hmac_sha256_cleanup_func = &cp_hmac_sha256_cleanup,
        .sha512_digest_init_func = &cp_sha512_digest_init,
        .sha512_digest_update_func = &cp_sha512_digest_update,
        .sha512_digest_final_func = &cp_sha512_digest_final,
        .sha512_digest_cleanup_func = &cp_sha512_digest_cleanup,
        .encrypt_func = &cp_encrypt,
        .decrypt_func = &cp_decrypt,
        .user_data = new_omemo,
    };

    signal_context_set_crypto_provider(new_omemo->context, &crypto_provider);
    signal_context_set_locking_functions(new_omemo->context, &lock_function, &unlock_function);

    signal_protocol_store_context_create(&new_omemo->store_context, new_omemo->context);

    struct signal_protocol_identity_key_store identity_key_store = {
        .get_identity_key_pair = &iks_get_identity_key_pair,
        .get_local_registration_id = &iks_get_local_registration_id,
        .save_identity = &iks_save_identity,
        .is_trusted_identity = &iks_is_trusted_identity,
        .destroy_func = &iks_destroy_func,
        .user_data = new_omemo,
    };

    signal_protocol_store_context_set_identity_key_store(
        new_omemo->store_context, &identity_key_store);

    struct signal_protocol_pre_key_store pre_key_store = {
        .load_pre_key = &pks_load_pre_key,
        .store_pre_key = &pks_store_pre_key,
        .contains_pre_key = &pks_contains_pre_key,
        .remove_pre_key = &pks_remove_pre_key,
        .destroy_func = &pks_destroy_func,
        .user_data = new_omemo,
    };

    signal_protocol_store_context_set_pre_key_store(
        new_omemo->store_context, &pre_key_store);

    struct signal_protocol_signed_pre_key_store signed_pre_key_store = {
        .load_signed_pre_key = &spks_load_signed_pre_key,
        .store_signed_pre_key = &spks_store_signed_pre_key,
        .contains_signed_pre_key = &spks_contains_signed_pre_key,
        .remove_signed_pre_key = &spks_remove_signed_pre_key,
        .destroy_func = &spks_destroy_func,
        .user_data = new_omemo,
    };

    signal_protocol_store_context_set_signed_pre_key_store(
        new_omemo->store_context, &signed_pre_key_store);

    struct signal_protocol_session_store session_store = {
        .load_session_func = &ss_load_session_func,
        .get_sub_device_sessions_func = &ss_get_sub_device_sessions_func,
        .store_session_func = &ss_store_session_func,
        .contains_session_func = &ss_contains_session_func,
        .delete_session_func = &ss_delete_session_func,
        .delete_all_sessions_func = &ss_delete_all_sessions_func,
        .destroy_func = &ss_destroy_func,
        .user_data = new_omemo,
    };

    signal_protocol_store_context_set_session_store(
        new_omemo->store_context, &session_store);

    struct signal_protocol_sender_key_store sender_key_store = {
        .store_sender_key = &sks_store_sender_key,
        .load_sender_key = &sks_load_sender_key,
        .destroy_func = &sks_destroy_func,
        .user_data = new_omemo,
    };

    signal_protocol_store_context_set_sender_key_store(
        new_omemo->store_context, &sender_key_store);

    signal_buffer *public_data, *private_data;
    iks_get_local_registration_id(new_omemo, &new_omemo->device_id);
    if (!iks_get_identity_key_pair(&public_data, &private_data, new_omemo))
    {
        ec_public_key *public_key = NULL;
        ec_private_key *private_key = NULL;
        curve_decode_point(&public_key, signal_buffer_data(public_data),
                signal_buffer_len(public_data), new_omemo->context);
        curve_decode_private_point(&private_key, signal_buffer_data(private_data),
                signal_buffer_len(private_data), new_omemo->context);
        ratchet_identity_key_pair_create(&new_omemo->identity, public_key, private_key);
    }
    weechat_printf(buffer, "%somemo: device = %d",
                   weechat_prefix("info"), new_omemo->device_id);

    *omemo = new_omemo;
}

void omemo__handle_devicelist(struct t_omemo *omemo, const char *jid,
                              xmpp_stanza_t *items)
{
    (void) omemo;

    xmpp_stanza_t *item = xmpp_stanza_get_child_by_name(items, "item");
    if (!item) return;
    xmpp_stanza_t *list = xmpp_stanza_get_child_by_name(item, "list");
    if (!list) return;
    signal_int_list *devicelist = signal_int_list_alloc();
    for (xmpp_stanza_t *device = xmpp_stanza_get_children(list);
         device; device = xmpp_stanza_get_next(device))
    {
        const char *name = xmpp_stanza_get_name(device);
        if (weechat_strcasecmp(name, "device") != 0)
            continue;

        const char *device_id = xmpp_stanza_get_id(device);
        if (!device_id)
            continue;

        signal_int_list_push_back(devicelist, strtol(device_id, NULL, 10));
    }
    if (dls_store_devicelist(jid, devicelist, omemo))
        weechat_printf(NULL, "%somemo: failed to handle devicelist (%s)",
                       weechat_prefix("error"), jid);
    signal_int_list_free(devicelist);
}

void omemo__handle_bundle(struct t_omemo *omemo, const char *jid,
                          uint32_t device_id, xmpp_stanza_t *items)
{
    xmpp_stanza_t *item = xmpp_stanza_get_child_by_name(items, "item");
    if (!item) return;
    xmpp_stanza_t *bundle = xmpp_stanza_get_child_by_name(item, "bundle");
    if (!bundle) return;
    xmpp_stanza_t *signedprekey = xmpp_stanza_get_child_by_name(bundle, "signedPreKeyPublic");
    if (!signedprekey) return;
    const char *signed_pre_key = xmpp_stanza_get_text(signedprekey);
    if (!signed_pre_key) return;
    const char *signed_pre_key_id = xmpp_stanza_get_attribute(signedprekey, "signedPreKeyId");
    if (!signed_pre_key_id) return;
    xmpp_stanza_t *signature = xmpp_stanza_get_child_by_name(bundle, "signedPreKeySignature");
    if (!signature) return;
    const char *key_signature = xmpp_stanza_get_text(signature);
    if (!key_signature) return;
    xmpp_stanza_t *identitykey = xmpp_stanza_get_child_by_name(bundle, "identityKey");
    if (!identitykey) return;
    const char *identity_key = xmpp_stanza_get_text(identitykey);
    if (!identity_key) return;
    xmpp_stanza_t *prekeys = xmpp_stanza_get_child_by_name(bundle, "prekeys");
    if (!prekeys) return;

    int num_prekeys = 0;
    for (xmpp_stanza_t *prekey = xmpp_stanza_get_children(prekeys);
         prekey; prekey = xmpp_stanza_get_next(prekey))
        num_prekeys++;
    struct t_pre_key **pre_keys = malloc(sizeof(struct t_pre_key) * num_prekeys);

    num_prekeys = -1;
    char **format = weechat_string_dyn_alloc(256);
    weechat_string_dyn_concat(format, "omemo bundle %s/%u:\n%s..SPK %u: %s\n%3$s..SKS: %s\n%3$s..IK: %s", -1);
    for (xmpp_stanza_t *prekey = xmpp_stanza_get_children(prekeys);
         prekey; prekey = xmpp_stanza_get_next(prekey))
    {
        const char *name = xmpp_stanza_get_name(prekey);
        if (weechat_strcasecmp(name, "preKeyPublic") != 0)
            continue;

        const char *pre_key_id = xmpp_stanza_get_attribute(prekey, "preKeyId");
        if (!pre_key_id)
            continue;
        const char *pre_key = xmpp_stanza_get_text(prekey);
        if (!pre_key)
            continue;

        pre_keys[++num_prekeys] = malloc(sizeof(struct t_pre_key));
        *pre_keys[num_prekeys] = (struct t_pre_key) {
            .id = pre_key_id,
            .public_key = pre_key,
        };

        weechat_string_dyn_concat(format, "\n%3$s..PK ", -1);
        weechat_string_dyn_concat(format, pre_key_id, -1);
        weechat_string_dyn_concat(format, ": ", -1);
        weechat_string_dyn_concat(format, pre_key, -1);
    }
    pre_keys[num_prekeys] = NULL;
    weechat_string_dyn_free(format, 1);

    struct t_pre_key signed_key = {
        .id = signed_pre_key_id,
        .public_key = signed_pre_key,
    };
    struct t_pre_key *signed_pre_keys[2] = { &signed_key, NULL };

    signal_protocol_address address = {
        .name = jid, .name_len = strlen(jid), .device_id = device_id };
    {
        ec_public_key *key;
        uint8_t *key_buf;
        size_t key_len = base64_decode(identity_key,
                strlen(identity_key), &key_buf);
        curve_decode_point(&key, key_buf, key_len, omemo->context);
        signal_protocol_identity_save_identity(omemo->store_context,
                &address, key);
    }
    bks_store_bundle(&address, pre_keys, signed_pre_keys,
        key_signature, identity_key, omemo);
}

char *omemo__decode(struct t_account *account, const char *jid,
                    xmpp_stanza_t *encrypted)
{
    struct t_omemo *omemo = account->omemo;
    uint8_t *key_data = NULL, *tag_data = NULL, *iv_data = NULL, *payload_data = NULL;
    size_t key_len = 0, tag_len = 0, iv_len = 0, payload_len = 0;

    xmpp_stanza_t *header = xmpp_stanza_get_child_by_name(encrypted, "header");
    if (!header) return NULL;
    xmpp_stanza_t *iv = xmpp_stanza_get_child_by_name(header, "iv");
    if (!iv) return NULL;
    const char *iv__text = xmpp_stanza_get_text(iv);
    if (!iv__text) return NULL;
    iv_len = base64_decode(iv__text, strlen(iv__text), &iv_data);
    if (iv_len != AES_IV_SIZE) return NULL;

    char **format = weechat_string_dyn_alloc(256);
    weechat_string_dyn_concat(format, "omemo msg %s:\n%s..IV: %s", -1);
    for (xmpp_stanza_t *key = xmpp_stanza_get_children(header);
         key; key = xmpp_stanza_get_next(key))
    {
        const char *name = xmpp_stanza_get_name(key);
        if (weechat_strcasecmp(name, "key") != 0)
            continue;

        const char *key_prekey = xmpp_stanza_get_attribute(key, "prekey");
        const char *key_id = xmpp_stanza_get_attribute(key, "rid");
        if (!key_id)
            continue;
        if (strtol(key_id, NULL, 10) != omemo->device_id)
            continue;
        xmpp_stanza_t *key_text = xmpp_stanza_get_children(key);
        const char *data = key_text ? xmpp_stanza_get_text(key_text) : NULL;
        if (!data)
            continue;
        key_len = base64_decode(data, strlen(data), &key_data);

        weechat_string_dyn_concat(format, "\n%2$s..K ", -1);
        if (key_prekey)
            weechat_string_dyn_concat(format, "*", -1);
        weechat_string_dyn_concat(format, key_id, -1);
        weechat_string_dyn_concat(format, ": ", -1);
        weechat_string_dyn_concat(format, data, -1);

        const char *source_id = xmpp_stanza_get_attribute(header, "sid");
        if (!source_id)
            continue;

        int ret;
        signal_protocol_address address = {
            .name = jid, .name_len = strlen(jid), .device_id = strtol(source_id, NULL, 10) };
        signal_message *key_message = NULL;
        signal_buffer *aes_key = NULL;
        if (key_prekey) {
            pre_key_signal_message *pre_key_message = NULL;
            if ((ret = pre_key_signal_message_deserialize(&pre_key_message,
                key_data, key_len, omemo->context))) return NULL;
            ec_public_key *identity_key = pre_key_signal_message_get_identity_key(pre_key_message);
          //uint32_t device_id = pre_key_signal_message_get_registration_id(pre_key_message);
          //uint32_t pre_key_id = pre_key_signal_message_get_pre_key_id(pre_key_message);
          //uint32_t signed_key_id = pre_key_signal_message_get_signed_pre_key_id(pre_key_message);
          //ec_public_key *base_key = pre_key_signal_message_get_base_key(pre_key_message);
            key_message = pre_key_signal_message_get_signal_message(pre_key_message);
            signal_buffer *identity_buf;
            if ((ret = ec_public_key_serialize(&identity_buf, identity_key))) return NULL;
            if ((ret = iks_save_identity(&address, signal_buffer_data(identity_buf),
                                    signal_buffer_len(identity_buf), omemo))) return NULL;

            session_cipher *cipher;
            if ((ret = session_cipher_create(&cipher, omemo->store_context,
                                        &address, omemo->context))) return NULL;
            if ((ret = session_cipher_decrypt_pre_key_signal_message(cipher,
                                                                pre_key_message,
                                                                0, &aes_key))) return NULL;
        } else {
            if ((ret = signal_message_deserialize(&key_message,
                key_data, key_len, omemo->context))) return NULL;
            session_cipher *cipher;
            if ((ret = session_cipher_create(&cipher, omemo->store_context,
                                        &address, omemo->context))) return NULL;
            if ((ret = session_cipher_decrypt_signal_message(cipher, key_message,
                                                        0, &aes_key))) return NULL;
        }

        if (!aes_key) return NULL;
        key_data = signal_buffer_data(aes_key);
        key_len = signal_buffer_len(aes_key);
        if (key_len >= AES_KEY_SIZE) {
            tag_len = key_len - AES_KEY_SIZE;
            tag_data = key_data + AES_KEY_SIZE;
            key_len = AES_KEY_SIZE;
        }
        else
        {
            return NULL;
        }

        char *aes_key64 = NULL;
        if (base64_encode(key_data, key_len, &aes_key64) && aes_key64)
        {
            weechat_string_dyn_concat(format, "\n%2$s..AES: ", -1);
            weechat_string_dyn_concat(format, aes_key64, -1);
            weechat_string_dyn_concat(format, " (", -1);
            snprintf(aes_key64, strlen(aes_key64), "%lu", key_len);
            weechat_string_dyn_concat(format, aes_key64, -1);
            weechat_string_dyn_concat(format, ")", -1);
        }
        if (tag_len && base64_encode(tag_data, tag_len, &aes_key64) && aes_key64)
        {
            weechat_string_dyn_concat(format, "\n%2$s..TAG: ", -1);
            weechat_string_dyn_concat(format, aes_key64, -1);
            weechat_string_dyn_concat(format, " (", -1);
            snprintf(aes_key64, strlen(aes_key64), "%lu", tag_len);
            weechat_string_dyn_concat(format, aes_key64, -1);
            weechat_string_dyn_concat(format, ")", -1);
        }
    }

    xmpp_stanza_t *payload = xmpp_stanza_get_child_by_name(encrypted, "payload");
    if (payload && (payload = xmpp_stanza_get_children(payload)))
    {
        const char *payload_text = xmpp_stanza_get_text(payload);
        if (!payload_text) return NULL;
        payload_len = base64_decode(payload_text, strlen(payload_text), &payload_data);
        weechat_string_dyn_concat(format, "\n%2$s..PL: ", -1);
        weechat_string_dyn_concat(format, payload_text, -1);
    }
  //weechat_printf(NULL, *format, jid, weechat_color("red"), iv__text);
    weechat_string_dyn_free(format, 1);

    if (!(payload_data && iv_data && key_data)) return NULL;
    if (iv_len != AES_IV_SIZE || key_len != AES_KEY_SIZE) return NULL;
    char *plaintext = NULL; size_t plaintext_len = 0;
    if (aes_decrypt(payload_data, payload_len, key_data, iv_data, tag_data, tag_len,
                    (uint8_t**)&plaintext, &plaintext_len) || plaintext)
    {
        plaintext[plaintext_len] = '\0';
        return plaintext;
    }
    return NULL;
}

xmpp_stanza_t *omemo__encode(struct t_account *account, const char *jid,
                             const char *unencrypted)
{
    struct t_omemo *omemo = account->omemo;
    uint8_t *key = NULL; uint8_t *iv = NULL;
    uint8_t *tag = NULL; size_t tag_len = 0;
    uint8_t *ciphertext = NULL; size_t ciphertext_len = 0;
    aes_encrypt((uint8_t*)unencrypted, strlen(unencrypted),
                &key, &iv, &tag, &tag_len,
                &ciphertext, &ciphertext_len);

    uint8_t *key_and_tag = malloc(sizeof(uint8_t) * (AES_KEY_SIZE+tag_len));
    memcpy(key_and_tag, key, AES_KEY_SIZE);
    free(key);
    memcpy(key_and_tag+AES_KEY_SIZE, tag, tag_len);
    free(tag);
    char *key64 = NULL;
    base64_encode(key_and_tag, AES_KEY_SIZE+tag_len, &key64);
    char *iv64 = NULL;
    base64_encode(iv, AES_IV_SIZE, &iv64);
    free(iv);
    char *ciphertext64 = NULL;
    base64_encode(ciphertext, ciphertext_len, &ciphertext64);
    free(ciphertext);

    xmpp_stanza_t *encrypted = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(encrypted, "encrypted");
    xmpp_stanza_set_ns(encrypted, "eu.siacs.conversations.axolotl");
    xmpp_stanza_t *header = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(header, "header");
    char device_id_str[10+1] = {0};
    snprintf(device_id_str, 10+1, "%u", omemo->device_id);
    xmpp_stanza_set_attribute(header, "sid", device_id_str);

    int ret, keycount = 0;
    signal_int_list *devicelist;
    const char *target = jid;
    for (int self = 0; self <= 1; self++)
    {
        if ((ret = dls_load_devicelist(&devicelist, target, omemo))) return NULL;
        for (size_t i = 0; i < signal_int_list_size(devicelist); i++)
        {
            uint32_t device_id = signal_int_list_at(devicelist, i);
            signal_protocol_address address = {
                .name = target, .name_len = strlen(target), .device_id = device_id};

            xmpp_stanza_t *header__key = xmpp_stanza_new(account->context);
            xmpp_stanza_set_name(header__key, "key");
            char device_id_str[10+1] = {0};
            snprintf(device_id_str, 10+1, "%u", device_id);
            xmpp_stanza_set_attribute(header__key, "rid", device_id_str);

            session_builder *builder = NULL;
            if (((ret = ss_contains_session_func(&address, omemo))) <= 0)
            {
                session_pre_key_bundle *bundle;
                if ((ret = bks_load_bundle(&bundle, &address, omemo))) continue;

                if ((ret = session_builder_create(&builder, omemo->store_context, &address, omemo->context))) continue;
                if ((ret = session_builder_process_pre_key_bundle(builder, bundle))) continue;
            }

            session_cipher *cipher;
            if ((ret = session_cipher_create(&cipher, omemo->store_context, &address, omemo->context))) continue;

            ciphertext_message *signal_message;
            if ((ret = session_cipher_encrypt(cipher, key_and_tag, AES_KEY_SIZE+tag_len, &signal_message))) continue;
            signal_buffer *record = ciphertext_message_get_serialized(signal_message);
            int prekey = ciphertext_message_get_type(signal_message) == CIPHERTEXT_PREKEY_TYPE
                ? 1 : 0;

            char *payload = NULL;
            base64_encode(signal_buffer_data(record), signal_buffer_len(record),
                    &payload);

            if (prekey)
                xmpp_stanza_set_attribute(header__key, "prekey",
                        prekey ? "true" : "false");
            stanza__set_text(account->context, header__key, with_free(payload));
            xmpp_stanza_add_child(header, header__key);
            xmpp_stanza_release(header__key);

            keycount++;

            signal_buffer_free(record);
          //SIGNAL_UNREF(signal_message);
            session_cipher_free(cipher);
            if (builder)
                session_builder_free(builder);
        }
        signal_int_list_free(devicelist);
        target = account_jid(account);
    }
    free(key_and_tag);

    if (keycount == 0) return NULL;

    xmpp_stanza_t *header__iv = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(header__iv, "iv");
    stanza__set_text(account->context, header__iv, with_noop(iv64));
    xmpp_stanza_add_child(header, header__iv);
    xmpp_stanza_release(header__iv);
    xmpp_stanza_add_child(encrypted, header);
    xmpp_stanza_release(header);
    xmpp_stanza_t *encrypted__payload = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(encrypted__payload, "payload");
    stanza__set_text(account->context, encrypted__payload, with_noop(ciphertext64));
    xmpp_stanza_add_child(encrypted, encrypted__payload);
    xmpp_stanza_release(encrypted__payload);

    free(iv64);
    free(key64);
    free(ciphertext64);
    return encrypted;
}

void omemo__free(struct t_omemo *omemo)
{
    if (omemo)
    {
        if (omemo->context) {
            signal_context_destroy(omemo->context);
            signal_protocol_store_context_destroy(omemo->store_context);
        }
        if (omemo->identity)
            ratchet_identity_key_pair_destroy(
                (signal_type_base *)omemo->identity);
        free(omemo->db_path);
        free(omemo);
    }
}
