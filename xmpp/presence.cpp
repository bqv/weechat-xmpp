// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdlib>
#include <strophe.h>

#include "stanza.hh"

xmpp_stanza_t *stanza__presence(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                xmpp_stanza_t **children, char *ns,
                                char *from, char *to, char *type)
{
    xmpp_stanza_t *parent = base ? base : xmpp_presence_new(context);
    xmpp_stanza_t **child = children;

    if (ns)
    {
        xmpp_stanza_set_ns(parent, ns);
        free(ns);
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

    if (type)
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
