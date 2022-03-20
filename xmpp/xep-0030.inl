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

    /* Service Discovery */
    struct xep0030 {
        struct query : virtual public spec {
            query() : spec("query") {
                xmlns<jabber_org::protocol::disco::info>();
            }
        };

        struct iq : virtual public spec {
            iq() : spec("iq") {}

            iq& query(query q = xep0030::query()) { child(q); return *this; }
        };
    };

}
