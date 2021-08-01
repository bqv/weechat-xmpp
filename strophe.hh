// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <functional>

extern "C" {
#include <strophe.h>
}

namespace xmpp {
    typedef std::unique_ptr<
        xmpp_ctx_t,
        std::function<void(xmpp_ctx_t*)>> xmpp_ctx_ptr;

    class context : public xmpp_ctx_ptr {
    public:
        context();
        context(xmpp_ctx_ptr ptr);
        context(xmpp_ctx_t *ptr);
        ~context();
    };

    void shutdown();
}
