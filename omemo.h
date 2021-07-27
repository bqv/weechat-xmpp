// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_OMEMO_H_
#define _WEECHAT_XMPP_OMEMO_H_

extern const char *OMEMO_ADVICE;

struct t_omemo
{
    struct signal_context *context;
    struct signal_protocol_store_context *store_context;

    struct {
        struct MDB_env *env;
        struct MDB_dbi *dbi;
    } db;

    struct ratchet_identity_key_pair *identity;

    uint32_t device_id;
};

void omemo__init(struct t_gui_buffer *buffer, struct t_omemo **omemo,
                 const char *account_name);

void omemo__serialize(struct t_omemo *omemo, char **device,
                      char **identity, size_t *identity_len);

void omemo__deserialize(struct t_omemo *omemo, const char *device,
                        const char *identity, size_t identity_len);

void omemo__free(struct t_omemo *omemo);

#endif /*WEECHAT_XMPP_OMEMO_H*/
