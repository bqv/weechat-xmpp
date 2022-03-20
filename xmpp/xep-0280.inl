// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <optional>
#include <string>

#include "node.hh"
#pragma GCC visibility push(default)
#include "ns.hh"
#pragma GCC visibility pop

namespace stanza {

    /* Message Carbons */
    struct xep0280 {
        struct enable : virtual public spec {
            enable() : spec("enable") {
                xmlns<urn::xmpp::carbons::_2>();
            }
        };

        struct iq : virtual public spec {
            iq() : spec("iq") {}

            iq& xep0280() { xmlns<jabber::client>(); return *this; }

            iq& enable(enable e = xep0280::enable()) { child(e); return *this; }
        };
    };

}
