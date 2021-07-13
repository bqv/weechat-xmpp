// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_STANZA_H_
#define _WEECHAT_XMPP_STANZA_H_

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
{ xmpp_free(string->pointer, string->value); }

static inline struct t_string *with_noop(const char *const value)
{
    struct t_string *string = malloc(sizeof(struct t_string));
    string->value = (char*)value;
    string->finalize = &t_string_noop;
    string->pointer = NULL;
    return string;
}

static inline struct t_string *with_free(char *value)
{
    struct t_string *string = malloc(sizeof(struct t_string));
    string->value = value;
    string->finalize = &t_string_free;
    string->pointer = NULL;
    return string;
}

static inline struct t_string *with_xmpp_free(char *value, xmpp_ctx_t *pointer)
{
    struct t_string *string = malloc(sizeof(struct t_string));
    string->value = value;
    string->finalize = &t_string_xmpp_free;
    string->pointer = pointer;
    return string;
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

xmpp_stanza_t *stanza__iq_pubsub_publish(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                         xmpp_stanza_t **children, struct t_string *node);

xmpp_stanza_t *stanza__iq_pubsub_publish_item(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                              xmpp_stanza_t **children, struct t_string *id);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_list(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                   xmpp_stanza_t **children, struct t_string *ns);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_list_device(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                          struct t_string *id);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                     xmpp_stanza_t **children, struct t_string *ns);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_signedPreKeyPublic(
    xmpp_ctx_t *context, xmpp_stanza_t *base, struct t_string *signedPreKeyId);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_signedPreKeySignature(
    xmpp_ctx_t *context, xmpp_stanza_t *base, struct t_string *signedPreKeySignature);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_identityKey(
    xmpp_ctx_t *context, xmpp_stanza_t *base, struct t_string *identityKey);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_preKeys(
    xmpp_ctx_t *context, xmpp_stanza_t *base, struct t_string *preKeys);

xmpp_stanza_t *stanza__iq_pubsub_publish_item_bundle_preKeys_preKeyPublic(
    xmpp_ctx_t *context, xmpp_stanza_t *base, struct t_string *preKeyPublic);

xmpp_stanza_t *stanza__iq_ping(xmpp_ctx_t *context, xmpp_stanza_t *base,
                               struct t_string *ns);

#endif /*WEECHAT_XMPP_STANZA_H*/
