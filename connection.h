// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_CONNECTION_H_
#define _WEECHAT_XMPP_CONNECTION_H_

void connection__init();

int connection__connect(xmpp_ctx_t *context, xmpp_conn_t **connection,
                        xmpp_log_t *logger, const char* jid,
                        const char* password, int tls);

void connection__process(xmpp_ctx_t *context, xmpp_conn_t *connection,
                         const unsigned long timeout);

int connection__route_message(xmpp_conn_t *connection,
                              const char *type, void *message);

#endif /*WEECHAT_XMPP_CONNECTION_H*/
