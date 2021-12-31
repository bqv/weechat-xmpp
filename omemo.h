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

    struct t_omemo_db *db;
    char *db_path;

    struct ratchet_identity_key_pair *identity;

    uint32_t device_id;
};

struct t_omemo_bundle_req
{
    char *id;
    char *jid;
    char *device;
    char *message_text;
};

struct t_omemo_devicelist_req
{
    char *id;
    struct t_omemo_bundle_req bundle_req;
};

xmpp_stanza_t *omemo__get_bundle(xmpp_ctx_t *context, char *from, char *to,
                                 struct t_omemo *omemo);

void omemo__init(struct t_gui_buffer *buffer, struct t_omemo **omemo,
                 const char *account_name);

void omemo__handle_devicelist(struct t_omemo *omemo, const char *jid,
                              xmpp_stanza_t *items);

void omemo__handle_bundle(struct t_omemo *omemo, const char *jid,
                          uint32_t device_id, xmpp_stanza_t *items);

char *omemo__decode(struct t_omemo *omemo, const char *jid,
                    xmpp_stanza_t *encrypted);

xmpp_stanza_t *omemo__encode(struct t_omemo *omemo, const char *jid,
                             uint32_t device_id, const char *unencrypted);

void omemo__free(struct t_omemo *omemo);

#endif /*WEECHAT_XMPP_OMEMO_H*/
