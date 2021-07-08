// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>

#include "omemo.h"

void omemo__init(struct t_omemo **omemo, uint32_t device,
                 struct t_identity *identity)
{
    int rc;

    srandom(time(NULL));

    omemo_bundle* bundle;
    rc = omemo_bundle_create(&bundle);
    if (rc)
        return;

    if (!device)
        device = random();
    omemo_bundle_set_device_id(bundle, device);

    if (identity)
        omemo_bundle_set_identity_key(bundle, identity->key, identity->length);
    else
    {
        identity = malloc(sizeof(*identity));
        identity->length = 4;
        identity->key = malloc(sizeof(*identity->key) * identity->length);

        identity->key[0] = random();
        identity->key[1] = random();
        identity->key[2] = random();
        identity->key[3] = random();

        omemo_bundle_set_identity_key(bundle, identity->key, identity->length);

        free(identity->key);
        free(identity);
    }

    *omemo = malloc(sizeof(**omemo));
    (*omemo)->provider.random_bytes_func = omemo_default_crypto_random_bytes;
    (*omemo)->provider.aes_gcm_encrypt_func = omemo_default_crypto_aes_gcm_encrypt;
    (*omemo)->provider.aes_gcm_decrypt_func = omemo_default_crypto_aes_gcm_decrypt;
    (*omemo)->provider.user_data_p = (void *)(*omemo);
    (*omemo)->bundle = bundle;
    (*omemo)->device_id = omemo_bundle_get_device_id(bundle);
    omemo_bundle_get_identity_key(bundle, &(*omemo)->identity.key, &(*omemo)->identity.length);

    omemo_devicelist *devicelist;
}

void omemo__free(struct t_omemo *omemo)
{
    free(omemo);
}
