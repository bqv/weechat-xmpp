// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_CONNECTION_H_
#define _WEECHAT_XMPP_CONNECTION_H_

extern xmpp_conn_t *xmpp_connection;

void xmpp_connection_init();

int xmpp_connection_autoconnect(const void *pointer, void *data, int remaining_calls);

void xmpp_connection_connect(const char* jid, const char* password);

int xmpp_connection_check_events(const void *pointer, void *data, int remaining_calls);

int xmpp_connection_route_message(xmpp_conn_t *connection,
                                  const char *type, void *message);

#endif /*WEECHAT_XMPP_CONNECTION_H*/
