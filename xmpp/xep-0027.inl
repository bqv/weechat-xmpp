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

namespace xml {

    class xep0027 : virtual public node {
    public:
        std::optional<std::string> signature() {
            auto child = get_children<jabber::x::signed_>("x");
            if (child.size() > 0)
                return child.front().get().text;
            return {};
        }

        std::optional<std::string> encrypted() {
            auto child = get_children<jabber::x::encrypted>("x");
            if (child.size() > 0)
                return child.front().get().text;
            return {};
        }
    };

}
