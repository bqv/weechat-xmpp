// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>

#include "node.hh"
#pragma GCC visibility push(default)
#include "ns.hh"
#pragma GCC visibility pop

namespace xml {

    class xep0319 : virtual public node {
    public:
        std::optional<std::chrono::system_clock::time_point> idle_since() {
            auto children = get_children<urn::xmpp::idle::_1>("idle");
            if (children.size() <= 0)
                return {};
            auto child = children.front().get();
            auto since = child.attributes.find("since");
            if (since == child.attributes.end())
                return {};
            try {
                return get_time(since->second);
            }
            catch (const std::invalid_argument& ex) {
                return {};
            }
        }
    };

}
