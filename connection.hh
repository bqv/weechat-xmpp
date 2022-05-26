// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <strophe.h>
#include "xmpp/ns.hh"
#include "strophe.hh"
#include "config.hh"

namespace weechat {
    class account;

    class connection
    {
    private:
        libstrophe::connection m_conn;

        enum class event {
            connect = XMPP_CONN_CONNECT,
            raw_connect = XMPP_CONN_RAW_CONNECT,
            disconnect = XMPP_CONN_DISCONNECT,
            fail = XMPP_CONN_FAIL,
        };

    public:
        weechat::account &account;

        connection(weechat::account &acc, libstrophe::context &ctx)
            : m_conn(ctx), account(acc) {
        }

        inline operator xmpp_conn_t*() {
            return m_conn;
        }

        inline auto send(xmpp_stanza_t *stanza) {
            m_conn.send(stanza);
        }

        inline auto context() {
            return m_conn.get_context();
        }

        inline bool connect_client(const char* altdomain, unsigned short altport, xmpp_conn_handler callback) {
            return m_conn.connect_client(altdomain, altport, callback, this) == XMPP_EOK;
        }

        inline auto handler_add(const char *name, const char *type, xmpp_handler callback) {
            return m_conn.handler_add(callback, nullptr, name, type, this);
        }

        template <typename X, std::enable_if_t<std::is_base_of<xmlns,X>::value, int> = 0>
        inline auto handler_add(const char *name, const char *type, xmpp_handler callback) {
            return m_conn.handler_add(callback, X(), name, type, this);
        }

        static void init();

        int connect(std::string jid, std::string password, weechat::tls_policy tls);

        void process(xmpp_ctx_t *context, const unsigned long timeout);

        bool version_handler(xmpp_stanza_t *stanza);
        bool presence_handler(xmpp_stanza_t *stanza);
        bool message_handler(xmpp_stanza_t *stanza);
        bool iq_handler(xmpp_stanza_t *stanza);

        bool conn_handler(event status, int error, xmpp_stream_error_t *stream_error);

        xmpp_stanza_t *get_caps(xmpp_stanza_t *reply, char **hash);
    };
}
