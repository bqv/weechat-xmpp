// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <strophe.h>

void connection__init();

int connection__connect(struct t_account *account, xmpp_conn_t **connection,
                        const char* jid, const char* password, int tls);

void connection__process(xmpp_ctx_t *context, xmpp_conn_t *connection,
                         const unsigned long timeout);
