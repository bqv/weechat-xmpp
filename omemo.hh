// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <functional>
#include <cstdint>
#include <string>
#include <strophe.h>
#include <lmdb++.h>
#include <signal_protocol.h>

#include "signal.hh"
struct t_account;

extern const char *OMEMO_ADVICE;

namespace weechat::xmpp {

struct t_pre_key {
    const char *id;
    const char *public_key;
};

struct omemo
{
    libsignal::context context;
    libsignal::store_context store_context;

    struct {
        lmdb::env env;
        lmdb::dbi dbi_omemo;
    } db;
    std::string db_path;

    libsignal::identity_key_pair identity;

    std::uint32_t device_id;

    class bundle_request
    {
    public:
        std::string id;
        std::string jid;
        std::string device;
        std::string message_text;
    };

    class devicelist_request
    {
    public:
        std::string id;
        bundle_request bundle_req;
    };

    ~omemo();

    inline operator bool() { return this->context && this->store_context &&
            this->identity && this->device_id != 0; }

    xmpp_stanza_t *get_bundle(xmpp_ctx_t *context, char *from, char *to);

    void init(struct t_gui_buffer *buffer, const char *account_name);

    void handle_devicelist(const char *jid, xmpp_stanza_t *items);

    void handle_bundle(const char *jid, std::uint32_t device_id,
                       xmpp_stanza_t *items);

    char *decode(struct t_account *account, const char *jid,
                 xmpp_stanza_t *encrypted);

    xmpp_stanza_t *encode(struct t_account *account, const char *jid,
                          const char *unencrypted);
};

}
