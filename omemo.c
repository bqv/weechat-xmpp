// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <gcrypt.h>
#include <signal_protocol.h>
#include <key_helper.h>
#include <curve.h>
#include <lmdb.h>
#include <strophe.h>

struct t_omemo_db {
    MDB_env *env;
    MDB_dbi dbi_omemo;
};

#include "plugin.h"
#include "account.h"
#include "omemo.h"

#define mdb_val_str(s) { \
    .mv_data = s, .mv_size = strlen(s), \
}

#define mdb_val_intptr(i) { \
    .mv_data = i, .mv_size = sizeof(*i), \
}

#define mdb_val_sizeof(t) { \
    .mv_data = NULL, .mv_size = sizeof(t), \
}

const char *OMEMO_ADVICE = "[OMEMO encrypted message (XEP-0384)]";

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
    MDB_txn *transaction;
    MDB_val k_local_private_key = mdb_val_str("local_private_key");
    MDB_val k_local_public_key = mdb_val_str("local_public_key");
    MDB_val v_local_private_key, v_local_public_key;

    // Get the local client's identity key pair
    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_local_private_key, &v_local_private_key) &&
        mdb_get(transaction, omemo->db->dbi_omemo,
                &k_local_public_key, &v_local_public_key))
    {
        *private_data = signal_buffer_create(v_local_private_key.mv_data, v_local_private_key.mv_size);
        *public_data = signal_buffer_create(v_local_public_key.mv_data, v_local_public_key.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
    }
    else
    {
        struct ratchet_identity_key_pair *identity;

        mdb_txn_abort(transaction);

        if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        }

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

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_local_private_key, &v_local_private_key, MDB_NOOVERWRITE) &&
            mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_local_public_key, &v_local_public_key, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                           weechat_prefix("error"));
            return -1;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
    }

    return 0;
}

int iks_get_local_registration_id(void *user_data, uint32_t *registration_id)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction;
    MDB_val k_local_registration_id = mdb_val_str("local_registration_id");
    MDB_val v_local_registration_id = mdb_val_sizeof(uint32_t);

    // Return the local client's registration ID
    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_local_registration_id,
                &v_local_registration_id))
    {
        *registration_id = *(uint32_t*)v_local_registration_id.mv_data;

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
    }
    else
    {
        mdb_txn_abort(transaction);

        if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        }

        signal_protocol_key_helper_generate_registration_id(
            (uint32_t*)&v_local_registration_id.mv_data, 0, omemo->context);

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_local_registration_id,
                    &v_local_registration_id, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                           weechat_prefix("error"));
            return -1;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
    }

    return 0;
}

int iks_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction;
    MDB_val k_registration_id = {
        .mv_data = NULL,
        .mv_size = strlen("registration_id_") + address->name_len,
    };
    MDB_val v_registration_id = mdb_val_intptr((uint32_t*)&address->device_id);
    MDB_val k_identity_key = {
        .mv_data = NULL,
        .mv_size = strlen("identity_key_") + address->name_len,
    };
    MDB_val v_identity_key = {.mv_data = key_data, .mv_size = key_len};

    k_registration_id.mv_data = malloc(sizeof(char) * (
                                           k_registration_id.mv_size + 1));
    snprintf(k_registration_id.mv_data, k_registration_id.mv_size,
             "registration_id_%s", address->name);
    k_identity_key.mv_data = malloc(sizeof(char) * (
                                           k_identity_key.mv_size + 1));
    snprintf(k_identity_key.mv_data, k_identity_key.mv_size,
             "identity_key_%s", address->name);

    // Save a remote client's identity key
    if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_put(transaction, omemo->db->dbi_omemo, &k_registration_id,
                &v_registration_id, 0) ||
        mdb_put(transaction, omemo->db->dbi_omemo, &k_identity_key,
                &v_identity_key, 0)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      return -1;
    };

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      return -1;
    };

    return 0;
}

int iks_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction;
    MDB_val k_registration_id = {
        .mv_data = NULL,
        .mv_size = strlen("registration_id_") + address->name_len,
    };
    MDB_val v_registration_id = mdb_val_intptr((uint32_t*)&address->device_id);
    MDB_val k_identity_key = {
        .mv_data = NULL,
        .mv_size = strlen("identity_key_") + address->name_len,
    };
    MDB_val v_identity_key = {.mv_data = key_data, .mv_size = key_len};
    int trusted = 1;

    k_registration_id.mv_data = malloc(sizeof(char) * (
                                           k_registration_id.mv_size + 1));
    snprintf(k_registration_id.mv_data, k_registration_id.mv_size,
             "registration_id_%s", address->name);
    k_identity_key.mv_data = malloc(sizeof(char) * (
                                           k_identity_key.mv_size + 1));
    snprintf(k_identity_key.mv_data, k_identity_key.mv_size,
             "identity_key_%s", address->name);

    // Verify a remote client's identity key
    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
        return -1;
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo, &k_registration_id,
                &v_registration_id) ||
        mdb_get(transaction, omemo->db->dbi_omemo, &k_identity_key,
                &v_identity_key)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                     weechat_prefix("error"));
      return -1;
    };

    if (*(uint32_t*)v_registration_id.mv_data != (uint32_t)address->device_id)
        trusted = 0;
    if (v_identity_key.mv_size != key_len ||
        memcmp(v_identity_key.mv_data, key_data, key_len) != 0)
        trusted = 0;

    if (mdb_txn_commit(transaction)) {
      weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                     weechat_prefix("error"));
      return -1;
    };

    return trusted;
}

void iks_destroy_func(void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    (void) omemo;
    // Function called to perform cleanup when the data store context is being destroyed
}

int pks_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction;
    MDB_val k_pre_key = mdb_val_str("pre_key");
    MDB_val v_pre_key;

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_pre_key, &v_pre_key))
    {
        *record = signal_buffer_create(v_pre_key.mv_data, v_pre_key.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
    }
    else
    {
        signal_protocol_key_helper_pre_key_list_node *pre_keys_list;
        session_pre_key *pre_key = NULL;

        mdb_txn_abort(transaction);

        /*
        signal_protocol_key_helper_generate_pre_keys(
            &pre_keys_list, 0, 100, omemo->context);
        pre_key = signal_protocol_key_helper_key_list_element(pre_keys_list);
        signal_protocol_key_helper_key_list_next(pre_keys_list);

        uint32_t id = session_pre_key_get_id(pre_key);
        session_pre_key_serialize(&record, pre_key);

        signal_protocol_key_helper_key_list_free(pre_keys_list);

        if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        }

        v_pre_key.mv_data = signal_buffer_data(*record);
        v_pre_key.mv_size = signal_buffer_len(*record);

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_pre_key, &v_pre_key, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                           weechat_prefix("error"));
            return -1;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
        */
        return -1;
    }

    return 0;
}

int pks_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    (void) pre_key_id;
    (void) record;
    (void) record_len;
    (void) user_data;
    return -1;
    struct t_omemo *omemo = (struct t_omemo *)user_data;
    MDB_txn *transaction;
    MDB_val k_pre_key = mdb_val_str("pre_key");
    MDB_val v_pre_key;

    if (mdb_txn_begin(omemo->db->env, NULL, MDB_RDONLY, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
    }

    if (mdb_get(transaction, omemo->db->dbi_omemo,
                &k_pre_key, &v_pre_key))
    {
        *record = signal_buffer_create(v_pre_key.mv_data, v_pre_key.mv_size);

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to close lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
    }
    else
    {
        signal_protocol_key_helper_pre_key_list_node *pre_keys_list;
        session_pre_key *pre_key = NULL;

        mdb_txn_abort(transaction);

        /*
        signal_protocol_key_helper_generate_pre_keys(
            &pre_keys_list, 0, 100, omemo->context);
        pre_key = signal_protocol_key_helper_key_list_element(pre_keys_list);
        signal_protocol_key_helper_key_list_next(pre_keys_list);

        uint32_t id = session_pre_key_get_id(pre_key);
        session_pre_key_serialize(&record, pre_key);

        signal_protocol_key_helper_key_list_free(pre_keys_list);

        if (mdb_txn_begin(omemo->db->env, NULL, 0, &transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        }

        v_pre_key.mv_data = signal_buffer_data(*record);
        v_pre_key.mv_size = signal_buffer_len(*record);

        if (mdb_put(transaction, omemo->db->dbi_omemo,
                    &k_pre_key, &v_pre_key, MDB_NOOVERWRITE))
        {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb value",
                           weechat_prefix("error"));
            return -1;
        };

        if (mdb_txn_commit(transaction)) {
            weechat_printf(NULL, "%sxmpp: failed to write lmdb transaction",
                           weechat_prefix("error"));
            return -1;
        };
        */
        return -1;
    }

    return 0;
}

int pks_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
    (void) pre_key_id;
    (void) user_data;
    return -1;
}

int pks_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
    (void) pre_key_id;
    (void) user_data;
    return -1;
}

void pks_destroy_func(void *user_data)
{
    (void) user_data;
}

int spks_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data)
{
    (void) record;
    (void) signed_pre_key_id;
    (void) user_data;
    return -1;
  //session_signed_pre_key *signed_pre_key;
  //int start_id = 0;
  //time_t timestamp = time(NULL);
  //signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, new_omemo->identity, 5, timestamp, new_omemo->context);
}

int spks_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    (void) signed_pre_key_id;
    (void) record;
    (void) record_len;
    (void) user_data;
    return -1;
}

int spks_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
    (void) signed_pre_key_id;
    (void) user_data;
    return -1;
}

int spks_remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
    (void) signed_pre_key_id;
    (void) user_data;
    return -1;
}

void spks_destroy_func(void *user_data)
{
    (void) user_data;
}

int ss_load_session_func(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data)
{
    (void) record;
    (void) user_record;
    (void) address;
    (void) user_data;
    return -1;
}

int ss_get_sub_device_sessions_func(signal_int_list **sessions, const char *name, size_t name_len, void *user_data)
{
    (void) sessions;
    (void) name;
    (void) name_len;
    (void) user_data;
    return -1;
}

int ss_store_session_func(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    (void) address;
    (void) record;
    (void) record_len;
    (void) user_record;
    (void) user_record_len;
    (void) user_data;
    return -1;
}

int ss_contains_session_func(const signal_protocol_address *address, void *user_data)
{
    (void) address;
    (void) user_data;
    return -1;
}

int ss_delete_session_func(const signal_protocol_address *address, void *user_data)
{
    (void) address;
    (void) user_data;
    return -1;
}

int ss_delete_all_sessions_func(const char *name, size_t name_len, void *user_data)
{
    (void) name;
    (void) name_len;
    (void) user_data;
    return -1;
}

void ss_destroy_func(void *user_data)
{
    (void) user_data;
}

int sks_store_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    (void) sender_key_name;
    (void) record;
    (void) record_len;
    (void) user_record;
    (void) user_record_len;
    (void) user_data;
    return -1;
}

int sks_load_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data)
{
    (void) record;
    (void) user_record;
    (void) sender_key_name;
    (void) user_data;
    return -1;
}

void sks_destroy_func(void *user_data)
{
    (void) user_data;
}

void omemo__log_emit_weechat(int level, const char *message, size_t len, void *user_data)
{
    struct t_gui_buffer *buffer = (struct t_gui_buffer*)user_data;

    static const char *log_level_name[5] = {"error", "warn", "notice", "info", "debug"};

    const char *tags = level < SG_LOG_DEBUG ? "no_log" : NULL;

    weechat_printf_date_tags(
        buffer, 0, tags,
        _("%somemo (%s): %.*s"),
        weechat_prefix("network"),
        log_level_name[level], len, message);
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

    mdb_env_create(&new_omemo->db->env);
    mdb_env_set_maxdbs(new_omemo->db->env, 50);
    mdb_env_set_mapsize(new_omemo->db->env, (size_t)1048576 * 100000); // 1MB * 100000
    char *path = weechat_string_eval_expression("${weechat_data_dir}/xmpp.omemo.db",
                                                NULL, NULL, NULL);
    if (mdb_env_open(new_omemo->db->env, path, MDB_NOSUBDIR, 0664) != 0)
    {
        return;
    }
    free(path);

    MDB_txn *parentTransaction = NULL;
    MDB_txn *transaction;
    if (mdb_txn_begin(new_omemo->db->env, parentTransaction, 0 ? MDB_RDONLY : 0, &transaction)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb transaction",
                       weechat_prefix("error"));
    }

    size_t db_name_len = strlen("omemo_") + strlen(account_name);
    char *db_name = malloc(sizeof(char) * (db_name_len + 1));
    snprintf(db_name, db_name_len+1, "identity_key_%s", account_name);
    if (mdb_dbi_open(transaction, db_name, MDB_DUPSORT | MDB_CREATE, &new_omemo->db->dbi_omemo)) {
        weechat_printf(NULL, "%sxmpp: failed to open lmdb database",
                       weechat_prefix("error"));
    }

    mdb_txn_abort(transaction);

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

    *omemo = new_omemo;
}

void omemo__serialize(struct t_omemo *omemo, char **device,
                      char **identity, size_t *identity_len)
{
    if (device)
    {
        size_t id_slen = log10(omemo->device_id) * 2;
        char *id = malloc(sizeof(char) * id_slen);
        snprintf(id, id_slen, "%d", omemo->device_id);

        *device = id;
    }
    if (identity)
    {
        signal_buffer *buffer;
        ratchet_identity_key_pair_serialize(&buffer, omemo->identity);

        size_t key_slen = signal_buffer_len(buffer) * 2;
        char *key = malloc(sizeof(char) * key_slen);
        size_t length = weechat_string_base_encode(64, (char*)signal_buffer_data(buffer),
                                                   signal_buffer_len(buffer), key);

        *identity = key;
        if (identity_len)
            *identity_len = length;
    }
}

void omemo__deserialize(struct t_omemo *omemo, const char *device,
                        const char *identity, size_t identity_len)
{
    if (device)
    {
        uint32_t id = device[0] ? atoi(device) : 0;

        omemo->device_id = id;
    }
    if (identity)
    {
        uint8_t *key = malloc(sizeof(uint8_t) * identity_len);
        size_t length = weechat_string_base_decode(64, identity, (char*)key);

        ratchet_identity_key_pair_deserialize(&omemo->identity,
                                              key, length, omemo->context);
    }
}

void omemo__free(struct t_omemo *omemo)
{
    if (omemo)
    {
        if (omemo->context)
            signal_context_destroy(omemo->context);
        if (omemo->identity)
            ratchet_identity_key_pair_destroy(
                (signal_type_base *)omemo->identity);
        free(omemo);
    }
}
