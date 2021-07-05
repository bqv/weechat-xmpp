// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_STANZA_H_
#define _WEECHAT_XMPP_STANZA_H_

xmpp_stanza_t *stanza__presence(xmpp_ctx_t *context, xmpp_stanza_t *base,
                                xmpp_stanza_t **children, const char *ns,
                                const char *from, const char *to, const char *type);

#endif /*WEECHAT_XMPP_STANZA_H*/
