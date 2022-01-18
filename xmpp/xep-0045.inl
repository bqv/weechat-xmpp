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

    class xep0045 : virtual public node {
    public:
        class x {
        private:
            struct decline {
                std::string reason;
                std::optional<jid> from;
                std::optional<jid> to;
            };

            struct destroy {
                std::string reason;
                std::optional<jid> target;
            };

            struct invite {
                std::string reason;
                std::optional<jid> from;
                std::optional<jid> to;
            };

            struct item {
                std::string reason;
            };

        public:
            x(const node& node) {
            }

            std::vector<decline> declines;
            std::vector<destroy> destroys;
            std::vector<invite> invites;
            std::vector<item> items;
            std::vector<std::string> passwords;
            std::vector<int> statuses;
        };

        std::optional<x> muc_user() {
            auto child = get_children<jabber_org::protocol::muc::user>("x");
            if (child.size() > 0)
                return child.front().get();
            return {};
        }
    };

}
