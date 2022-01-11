// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "strophe.hh"

namespace xmpp {
    extern "C" {
#include <strophe.h>
    }

    template<typename UserData>
<<<<<<< Updated upstream
    context::context(UserData& data)
        : context(xmpp_ctx_new(nullptr, const_cast<xmpp_log_t*>(static_cast<const xmpp_log_t*>(std::any_cast<logger<UserData>>(&this->m_logger))))) {
        this->m_logger = logger(data);
=======
    context::context(UserData& data) {
        this->m_logger.emplace<logger<UserData>>(data);
        auto logger_ptr = std::any_cast<logger<UserData>>(&this->m_logger);
        xmpp_ctx_t *ctx_ptr = xmpp_ctx_new(nullptr, static_cast<xmpp_log_t*>(logger_ptr));
        xmpp_ctx_ptr::operator=(xmpp_ctx_ptr(ctx_ptr, &xmpp_ctx_free));
>>>>>>> Stashed changes
    }

    template<typename UserData>
    logger<UserData>::logger(UserData& data)
        : m_data(data) {
        this->handler = [] (void *const userdata, const xmpp_log_level_t level,
                            const char *const area, const char *const msg) {
            UserData& data = static_cast<logger<UserData>*>(userdata)->m_data;
            logger::emit_weechat(data, level, area, msg);
        };
        this->userdata = this;
    }
}

namespace xml {
    extern "C" {
#include <libxml/xmlwriter.h>
    }

    template<typename T>
    void set_error_context(T *context) {
        xmlGenericErrorContext = context;
    }
}
