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

    /* Last User Interaction in Presence */
    class xep0319 : virtual public node {
    private:
        std::optional<std::optional<std::chrono::system_clock::time_point>> _idle_since;
    public:
        std::optional<std::chrono::system_clock::time_point> idle_since() {
            if (!_idle_since)
            {
                auto children = get_children<urn::xmpp::idle::_1>("idle");
                if (children.size() <= 0)
                    _idle_since.emplace(std::nullopt);
                else {
                auto since = children.front().get().get_attr("since");
                if (!since)
                    _idle_since.emplace(std::nullopt);
                else {
                try {
                    _idle_since = get_time(*since);
                }
                catch (const std::invalid_argument& ex) {
                    _idle_since.emplace(std::nullopt);
                }
                }
                }
            }
            return *_idle_since;
        }
    };

}
