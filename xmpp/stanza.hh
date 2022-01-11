// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#ifdef __cplusplus
#include <cstdlib>
#include <strophe.h>
#endif

struct t_string
{
    char *value;

    void (*finalize)(struct t_string *);
    void *pointer;
};

static void t_string_noop(struct t_string *string)
{ (void)string; }

static void t_string_free(struct t_string *string)
{ free(string->value); }

static void t_string_xmpp_free(struct t_string *string)
{ xmpp_free((const xmpp_ctx_t*)string->pointer, string->value); }

static inline struct t_string *with_noop(const char *const value)
{
    struct t_string *string = (struct t_string *)malloc(sizeof(struct t_string));
    string->value = (char*)value;
    string->finalize = &t_string_noop;
    string->pointer = NULL;
    return string;
}

static inline struct t_string *with_free(char *value)
{
    struct t_string *string = (struct t_string *)malloc(sizeof(struct t_string));
    string->value = value;
    string->finalize = &t_string_free;
    string->pointer = NULL;
    return string;
}

static inline struct t_string *with_xmpp_free(char *value, xmpp_ctx_t *pointer)
{
    struct t_string *string = (struct t_string *)malloc(sizeof(struct t_string));
    string->value = value;
    string->finalize = &t_string_xmpp_free;
    string->pointer = pointer;
    return string;
}

static inline void stanza__set_text(xmpp_ctx_t *context, xmpp_stanza_t *parent,
                                    struct t_string *value)
{
    xmpp_stanza_t *text = xmpp_stanza_new(context);

    if (value)
    {
        xmpp_stanza_set_text(text, value->value);
        xmpp_stanza_add_child(parent, text);
        value->finalize(value);
        free(value);
    }

    xmpp_stanza_release(text);
}

xmpp_stanza_t *stanza__presence(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                xmpp_stanza_t **children, const char *ns,
                                char *from, char *to, const char *type);

xmpp_stanza_t *stanza__iq(xmpp_ctx_t *context, xmpp_stanza_t *base,
                          xmpp_stanza_t **children, char *ns, char *id,
                          char *from, char *to, char *type);

xmpp_stanza_t *stanza__iq_pubsub(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                 xmpp_stanza_t **children, struct t_string *ns);

xmpp_stanza_t *stanza__iq_pubsub_items(xmpp_ctx_t *context, xmpp_stanza_t *base, char *node);

xmpp_stanza_t *stanza__iq_pubsub_subscribe(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                           struct t_string *node, struct t_string *jid);

xmpp_stanza_t *stanza__iq_pubsub_publish(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                         xmpp_stanza_t **children, struct t_string *node);

xmpp_stanza_t *stanza__iq_pubsub_publish_item(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                              xmpp_stanza_t **children, struct t_string *id);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_list(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                   xmpp_stanza_t **children, struct t_string *ns);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_list_device(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                          struct t_string *id, struct t_string *label);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                     xmpp_stanza_t **children, struct t_string *ns);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_signedPreKeyPublic(
    xmpp_ctx_t *context, xmpp_stanza_t *base, xmpp_stanza_t **children, struct t_string *signedPreKeyId);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_signedPreKeySignature(
    xmpp_ctx_t *context, xmpp_stanza_t *base, xmpp_stanza_t **children);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_identityKey(
    xmpp_ctx_t *context, xmpp_stanza_t *base, xmpp_stanza_t **children);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_prekeys(
    xmpp_ctx_t *context, xmpp_stanza_t *base, xmpp_stanza_t **children);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_prekeys_preKeyPublic(
    xmpp_ctx_t *context, xmpp_stanza_t *base, xmpp_stanza_t **children, struct t_string *preKeyId);

xmpp_stanza_t *stanza__iq_enable(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                 struct t_string *ns);

xmpp_stanza_t *stanza__iq_ping(xmpp_ctx_t *context, xmpp_stanza_t *base,
                               struct t_string *ns);

xmpp_stanza_t *stanza__iq_query(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                struct t_string *ns, struct t_string *node);
