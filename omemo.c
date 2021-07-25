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
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "account.h"
#include "omemo.h"

const char *OMEMO_ADVICE = "[OMEMO encrypted message (XEP-0384)]";

signal_type_base* signal_type_ref_vapi(void* instance) {
    if (!(instance != NULL))
        return NULL;
    signal_type_ref(instance);
    return instance;
}

signal_type_base* signal_type_unref_vapi(void* instance) {
    if (!(instance != NULL))
        return NULL;
    signal_type_unref(instance);
    return NULL;
}

void signal_protocol_address_free(signal_protocol_address* ptr) {
    if (!(ptr != NULL))
        return;
    if (ptr->name) {
        free((void*)ptr->name);
    }
    return free(ptr);
}

void signal_protocol_address_set_name(signal_protocol_address* self, const char* name) {
    if (!(self != NULL))
        return;
    if (!(name != NULL))
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
    if (!(self != NULL))
        return NULL;
    if (!(self->name != NULL))
        return 0;
    char* res = malloc(sizeof(char) * (self->name_len + 1));
    memcpy(res, self->name, self->name_len);
    res[self->name_len] = 0;
    return res;
}

int32_t signal_protocol_address_get_device_id(signal_protocol_address* self) {
    if (!(self != NULL))
        return -1;
    return self->device_id;
}

void signal_protocol_address_set_device_id(signal_protocol_address* self, int32_t device_id) {
    if (!(self != NULL))
        return;
    self->device_id = device_id;
}

signal_protocol_address* signal_protocol_address_new(const char* name, int32_t device_id) {
    if (!(name != NULL))
        return NULL;
    signal_protocol_address* address = malloc(sizeof(signal_protocol_address));
    address->device_id = -1;
    address->name = NULL;
    signal_protocol_address_set_name(address, name);
    signal_protocol_address_set_device_id(address, device_id);
    return address;
}

int signal_randomize(uint8_t *data, size_t len) {
    gcry_randomize(data, len, GCRY_STRONG_RANDOM);
    return SG_SUCCESS;
}

int signal_random_generator(uint8_t *data, size_t len, void *user_data) {
    (void) user_data;

    gcry_randomize(data, len, GCRY_STRONG_RANDOM);
    return SG_SUCCESS;
}

int signal_hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data) {
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

int signal_hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data) {
    (void) user_data;

    gcry_mac_hd_t* ctx = hmac_context;

    if (gcry_mac_write(*ctx, data, data_len)) return SG_ERR_UNKNOWN;

    return SG_SUCCESS;
}

int signal_hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data) {
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

void signal_hmac_sha256_cleanup(void *hmac_context, void *user_data) {
    (void) user_data;

    gcry_mac_hd_t* ctx = hmac_context;
    if (ctx) {
        gcry_mac_close(*ctx);
        free(ctx);
    }
}

int signal_sha512_digest_init(void **digest_context, void *user_data) {
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

int signal_sha512_digest_update(void *digest_context, const uint8_t *data, size_t data_len, void *user_data) {
    (void) user_data;

    gcry_md_hd_t* ctx = digest_context;

    gcry_md_write(*ctx, data, data_len);

    return SG_SUCCESS;
}

int signal_sha512_digest_final(void *digest_context, signal_buffer **output, void *user_data) {
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

void signal_sha512_digest_cleanup(void *digest_context, void *user_data) {
    (void) user_data;

    gcry_md_hd_t* ctx = digest_context;
    if (ctx) {
        gcry_md_close(*ctx);
        free(ctx);
    }
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

int signal_encrypt(signal_buffer **output,
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

int signal_decrypt(signal_buffer **output,
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

void lock_function(void *user_data)
{
    (void) user_data;
}

void unlock_function(void *user_data)
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

int omemo__signal_init(struct t_gui_buffer *buffer, struct t_omemo *omemo)
{
    signal_context *global_context;

    gcry_check_version(NULL);

    signal_context_create(&global_context, buffer);
    signal_context_set_log_function(global_context, &omemo__log_emit_weechat);

    struct signal_crypto_provider provider = {
        .random_func = &signal_random_generator,
        .hmac_sha256_init_func = &signal_hmac_sha256_init,
        .hmac_sha256_update_func = &signal_hmac_sha256_update,
        .hmac_sha256_final_func = &signal_hmac_sha256_final,
        .hmac_sha256_cleanup_func = &signal_hmac_sha256_cleanup,
        .sha512_digest_init_func = &signal_sha512_digest_init,
        .sha512_digest_update_func = &signal_sha512_digest_update,
        .sha512_digest_final_func = &signal_sha512_digest_final,
        .sha512_digest_cleanup_func = &signal_sha512_digest_cleanup,
        .encrypt_func = &signal_encrypt,
        .decrypt_func = &signal_decrypt,
        .user_data = buffer,
    };

    signal_context_set_crypto_provider(global_context, &provider);
    signal_context_set_locking_functions(global_context, &lock_function, &unlock_function);

    signal_protocol_key_helper_pre_key_list_node *pre_keys_head;
    session_signed_pre_key *signed_pre_key;
    int start_id = 0;
    time_t timestamp = time(NULL);

    signal_protocol_key_helper_generate_identity_key_pair(&omemo->identity, global_context);
    signal_protocol_key_helper_generate_registration_id(&omemo->device_id, 0, global_context);
    signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, start_id, 100, global_context);
    signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, omemo->identity, 5, timestamp, global_context);

    /* Store pre keys in the pre key store. */
    /* Store signed pre key in the signed pre key store. */

    omemo->context = global_context;

    return SG_SUCCESS;
}

void omemo__init(struct t_gui_buffer *buffer, struct t_omemo **omemo,
                 char **device, char **identity)
{
    struct t_omemo *new_omemo;

    new_omemo = calloc(1, sizeof(**omemo));

    omemo__deserialize(new_omemo, *device, *identity, strlen(*identity));

    omemo__signal_init(buffer, new_omemo);

    omemo__serialize(new_omemo, device, identity, NULL);

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
