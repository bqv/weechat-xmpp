// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _XMPP_CONNECTION_H_
#define _XMPP_CONNECTION_H_

extern xmpp_ctx_t *xmpp_context;

extern xmpp_conn_t *xmpp_connection;

void xmpp_connection_init();

void xmpp_connection_connect(xmpp_conn_t *connection);

int xmpp_connection_route_message(xmpp_conn_t *connection,
                                  const char *type, json_object *message);

#endif /*XMPP_CONNECTION_H*/
