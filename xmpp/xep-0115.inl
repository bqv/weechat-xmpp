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

namespace xml{

    class xep0115  : virtual public node {
    public:
        struct caps {
            caps(::xml::node& node) {
                if (auto attr = node.get_attr("ext"))
                    ext = *attr;
                if (auto attr = node.get_attr("hash"))
                    hashalgo = *attr;
                if (auto attr = node.get_attr("node"))
                    this->node = *attr;
                if (auto attr = node.get_attr("ver"))
                    verification = *attr;
            };

            std::optional<std::string> ext;
            std::string hashalgo;
            std::string node;
            std::string verification;
        };

    private:
        std::optional<std::optional<caps>> _capabilities;
    public:
        std::optional<caps> capabilities() {
            if (!_capabilities)
            {
                auto child = get_children<jabber_org::protocol::caps>("c");
                if (child.size() > 0)
                    _capabilities = caps(child.front().get());
                _capabilities.emplace(std::nullopt);
            }
            return *_capabilities;
        }
    };

}
