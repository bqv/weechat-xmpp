// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <strophe.h>

#include "stanza.h"

xmpp_stanza_t *stanza__iq(xmpp_ctx_t *context, xmpp_stanza_t *base,
                          xmpp_stanza_t **children, char *ns, char *id,
                          char *from, char *to, char *type)
{
    xmpp_stanza_t *parent = base ? base : xmpp_iq_new(context, type, id);
    xmpp_stanza_t **child = children;

    if (ns)
    {
        xmpp_stanza_set_ns(parent, ns);
        free(ns);
    }

    if (base && id)
    {
        xmpp_stanza_set_id(parent, id);
        free(id);
    }

    if (from)
    {
        xmpp_stanza_set_from(parent, from);
        free(from);
    }

    if (to)
    {
        xmpp_stanza_set_to(parent, to);
        free(to);
    }

    if (base && type)
    {
        xmpp_stanza_set_attribute(parent, "type", type);
        free(type);
    }

    while (*child)
    {
        xmpp_stanza_add_child(parent, *child);
        xmpp_stanza_release(*child);

        ++child;
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_pubsub(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                 xmpp_stanza_t **children, struct t_string *ns)
{
    xmpp_stanza_t *parent = base;
    xmpp_stanza_t **child = children;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "pubsub");
    }

    if (ns)
    {
        xmpp_stanza_set_ns(parent, ns->value);
        ns->finalize(ns);
        free(ns);
    }

    while (*child)
    {
        xmpp_stanza_add_child(parent, *child);
        xmpp_stanza_release(*child);

        ++child;
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_pubsub_items(xmpp_ctx_t *context, xmpp_stanza_t *base, char *node)
{
    xmpp_stanza_t *parent = base;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "items");
    }

    if (node)
    {
        xmpp_stanza_set_attribute(parent, "node", node);
        free(node);
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_pubsub_publish(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                         xmpp_stanza_t **children, struct t_string *node)
{
    xmpp_stanza_t *parent = base;
    xmpp_stanza_t **child = children;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "publish");
    }

    if (node)
    {
        xmpp_stanza_set_attribute(parent, "node", node->value);
        node->finalize(node);
        free(node);
    }

    while (*child)
    {
        xmpp_stanza_add_child(parent, *child);
        xmpp_stanza_release(*child);

        ++child;
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_pubsub_publish_item(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                              xmpp_stanza_t **children, struct t_string *id)
{
    xmpp_stanza_t *parent = base;
    xmpp_stanza_t **child = children;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "item");
    }

    if (id)
    {
        xmpp_stanza_set_id(parent, id->value);
        id->finalize(id);
        free(id);
    }

    while (*child)
    {
        xmpp_stanza_add_child(parent, *child);
        xmpp_stanza_release(*child);

        ++child;
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_pubsub_publish_item_list(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                   xmpp_stanza_t **children, struct t_string *ns)
{
    xmpp_stanza_t *parent = base;
    xmpp_stanza_t **child = children;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "list");
    }

    if (ns)
    {
        xmpp_stanza_set_ns(parent, ns->value);
        ns->finalize(ns);
        free(ns);
    }

    while (*child)
    {
        xmpp_stanza_add_child(parent, *child);
        xmpp_stanza_release(*child);

        ++child;
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_pubsub_publish_item_list_device(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                                          struct t_string *id)
{
    xmpp_stanza_t *parent = base;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "device");
    }

    if (id)
    {
        xmpp_stanza_set_id(parent, id->value);
        id->finalize(id);
        free(id);
    }

    return parent;
}

xmpp_stanza_t *stanza__iq_ping(xmpp_ctx_t *context, xmpp_stanza_t *base,
                               struct t_string *ns)
{
    xmpp_stanza_t *parent = base;

    if (!parent)
    {
        parent = xmpp_stanza_new(context);
        xmpp_stanza_set_name(parent, "ping");
    }

    if (ns)
    {
        xmpp_stanza_set_ns(parent, ns->value);
        ns->finalize(ns);
        free(ns);
    }

    return parent;
}
