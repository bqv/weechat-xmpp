// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <gcrypt.h>
#include <signal_protocol.h>

#include "omemo.h"

/*
char *omemo__signal_init()
{
    signal_protocol_store_context *store_context_p = NULL;

    signal_protocol_session_store session_store = {
        .load_session_func = &axc_db_session_load,
        .get_sub_device_sessions_func = &axc_db_session_get_sub_device_sessions,
        .store_session_func = &axc_db_session_store,
        .contains_session_func = &axc_db_session_contains,
        .delete_session_func = &axc_db_session_delete,
        .delete_all_sessions_func = &axc_db_session_delete_all,
        .destroy_func = &axc_db_session_destroy_store_ctx,
        .user_data = ctx_p
    };
    signal_protocol_pre_key_store pre_key_store = {
        .load_pre_key = &axc_db_pre_key_load,
        .store_pre_key = &axc_db_pre_key_store,
        .contains_pre_key = &axc_db_pre_key_contains,
        .remove_pre_key = &axc_db_pre_key_remove,
        .destroy_func = &axc_db_pre_key_destroy_ctx,
        .user_data = ctx_p
    };
    signal_protocol_signed_pre_key_store signed_pre_key_store = {
        .load_signed_pre_key = &axc_db_signed_pre_key_load,
        .store_signed_pre_key = &axc_db_signed_pre_key_store,
        .contains_signed_pre_key = &axc_db_signed_pre_key_contains,
        .remove_signed_pre_key = &axc_db_signed_pre_key_remove,
        .destroy_func = &axc_db_signed_pre_key_destroy_ctx,
        .user_data = ctx_p
    };
    signal_protocol_identity_key_store identity_key_store = {
        .get_identity_key_pair = &axc_db_identity_get_key_pair,
        .get_local_registration_id = &axc_db_identity_get_local_registration_id,
        .save_identity = &axc_db_identity_save,
        .is_trusted_identity = &axc_db_identity_always_trusted,
        .destroy_func = &axc_db_identity_destroy_ctx,
        .user_data = ctx_p
    };

    if (signal_context_create(&(ctx_p->axolotl_global_context_p), ctx_p)) {
        return "failed to create global axolotl context";
    }

    signal_crypto_provider crypto_provider = {
        .random_func = random_bytes,
        .hmac_sha256_init_func = hmac_sha256_init,
        .hmac_sha256_update_func = hmac_sha256_update,
        .hmac_sha256_final_func = hmac_sha256_final,
        .sha512_digest_init_func = sha512_digest_init,
        .sha512_digest_update_func = sha512_digest_update,
        .sha512_digest_final_func = sha512_digest_final,
        .encrypt_func = aes_encrypt,
        .decrypt_func = aes_decrypt,
        .user_data = ctx_p
    };
    if (signal_context_set_crypto_provider(ctx_p->axolotl_global_context_p, &crypto_provider)) {
        return "failed to set crypto provider";
    }

    if (signal_context_set_locking_functions(ctx_p->axolotl_global_context_p, recursive_mutex_lock, recursive_mutex_unlock)) {
        return "failed to set locking functions";
    }

    if (signal_protocol_store_context_create(&store_context_p, ctx_p->axolotl_global_context_p)) {
        return "failed to create store context";
    }

    if (signal_protocol_store_context_set_session_store(store_context_p, &session_store)) {
        return "failed to create session store";
    }

    if (signal_protocol_store_context_set_pre_key_store(store_context_p, &pre_key_store)) {
        return "failed to set pre key store";
    }

    if (signal_protocol_store_context_set_signed_pre_key_store(store_context_p, &signed_pre_key_store)) {
        return "failed to set signed pre key store";
    }

    if (signal_protocol_store_context_set_identity_key_store(store_context_p, &identity_key_store)) {
        return "failed to set identity key store";
    }

    ctx_p->axolotl_store_context_p = store_context_p;

    return NULL;
}
*/

void omemo__init(struct t_omemo **omemo, uint32_t device,
                 struct t_identity *const identity)
{
    struct t_omemo *new_omemo;

    srandom(time(NULL));

    new_omemo = calloc(1, sizeof(**omemo));

    new_omemo->identity = malloc(sizeof(*identity));
    if (identity)
    {
        new_omemo->identity->length = identity->length;
        new_omemo->identity->key = calloc(identity->length, sizeof(*identity->key));
        memcpy(new_omemo->identity->key, identity->key,
               identity->length * sizeof(*identity->key));
    }
    else
    {
        new_omemo->identity->length = 4;
        new_omemo->identity->key = calloc(identity->length, sizeof(*identity->key));

        new_omemo->identity->key[0] = random();
        new_omemo->identity->key[1] = random();
        new_omemo->identity->key[2] = random();
        new_omemo->identity->key[3] = random();
    }

    new_omemo->device_id = device ? device : random();

    *omemo = new_omemo;
}

void omemo__free(struct t_omemo *omemo)
{
    if (omemo)
    {
        if (omemo->identity->key)
            free(omemo->identity->key);
        if (omemo->identity)
            free(omemo->identity);
        free(omemo);
    }
}
