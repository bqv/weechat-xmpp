// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "strophe.hh"

xmpp_log_t* logger = nullptr;

namespace xmpp {
    context::context()
        : context(xmpp_ctx_new(nullptr, logger)) {
    }

    context::context(xmpp_ctx_ptr ptr)
        : xmpp_ctx_ptr(std::move(ptr)) {
    }

    context::context(xmpp_ctx_t *ptr)
        : context(std::move(xmpp_ctx_ptr(
            ptr, [this] (xmpp_ctx_t *ctx) {
                xmpp_ctx_free(ctx);
            }
        ))) {
    }

    context::~context() {
        this->reset(nullptr);
    }

    void shutdown() {
        xmpp_shutdown();
    }
}
