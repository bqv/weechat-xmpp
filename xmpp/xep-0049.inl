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

    /* Private XML Storage */
    struct xep0049 {
        struct storage : virtual public spec {
            storage() : spec("storage") {
                xmlns<::storage::bookmarks>();
            }
        };

        struct query : virtual public spec {
            query() : spec("query") {
                xmlns<jabber::iq::private_>();
            }

            query& bookmarks(storage s = xep0049::storage()) { child(s); return *this; }
        };

        struct iq : virtual public spec {
            iq() : spec("iq") {}

            iq& xep0049() { return *this; }

            iq& query(xep0049::query q = {}) { child(q); return *this; }
        };
    };

}
