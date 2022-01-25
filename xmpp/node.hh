// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <fmt/core.h>
#include <strophe.h>

std::string get_name(xmpp_stanza_t *stanza);

std::optional<std::string> get_attribute(xmpp_stanza_t *stanza, const char *name);

std::string get_text(xmpp_stanza_t *stanza);

std::chrono::system_clock::time_point get_time(const std::string& text);

class jid {
private:
    static const std::regex pattern;

public:
    jid(xmpp_ctx_t *context, std::string s);

    operator std::string&() { return full; }

    std::string full;
    std::string_view bare;
    std::string_view local;
    std::string_view domain;
    std::string_view resource;

    bool is_bare() const;
};

namespace xml {

    class node {
    protected:
        explicit node();

    public:
        inline node(xmpp_ctx_t *context, xmpp_stanza_t *stanza) : context(context) {
            bind(context, stanza);
        }

        xmpp_ctx_t *context;

        std::optional<std::string> name;

        std::optional<std::string> id;
        std::optional<std::string> ns;

        std::map<std::string, std::string> attributes;
        std::vector<node> children;

        std::string text;

        virtual void bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza);

        inline std::optional<std::string>
        get_attr(const std::string& name) {
            auto attribute = attributes.find(name);
            if (attribute != attributes.end())
                return attribute->second;
            return {};
        }

        template<typename xmlns>
        inline std::vector<std::reference_wrapper<node>>
        get_children(std::string_view name) {
            std::vector<std::reference_wrapper<node>> list;
            std::copy_if(children.begin(), children.end(),
                         std::back_inserter(list),
                         [&](node& x) {
                             return x.name == name
                                 && x.ns == std::string_view(xmlns());
                         });
            return list;
        }

        inline std::vector<std::reference_wrapper<node>>
        get_children(std::string_view name) {
            std::vector<std::reference_wrapper<node>> list;
            std::copy_if(children.begin(), children.end(),
                         std::back_inserter(list),
                         [&](node& x) {
                             return x.name == name;
                         });
            return list;
        }
    };

}

#include "xep-0027.inl"
#include "xep-0045.inl"
#include "xep-0115.inl"
#include "xep-0319.inl"

namespace xml {

    class message : virtual public node,
                    public xep0027 {
    public:
        inline message(xmpp_ctx_t *context, xmpp_stanza_t *stanza) : node(context, stanza) {
            bind(context, stanza);
        }

        std::optional<jid> from;
        std::optional<jid> to;

        std::optional<std::string> type;

        void bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) override;
    };

    class presence : virtual public node,
                     public xep0027, public xep0045, public xep0115, public xep0319 {
    public:
        inline presence(xmpp_ctx_t *context, xmpp_stanza_t *stanza) : node(context, stanza) {
            bind(context, stanza);
        }

        std::optional<jid> from;
        std::optional<jid> to;

        std::optional<std::string> type;

        std::optional<std::string> show();
        std::optional<std::string> status();

        void bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) override;
    };

    class iq : virtual public node {
    public:
        inline iq(xmpp_ctx_t *context, xmpp_stanza_t *stanza) : node(context, stanza) {
            bind(context, stanza);
        }

        std::optional<jid> from;
        std::optional<jid> to;

        std::optional<std::string> type;

        void bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) override;
    };

    class error : virtual public node {
    public:
        inline error(xmpp_ctx_t *context, xmpp_stanza_t *stanza) : node(context, stanza) {
            bind(context, stanza);
        }

        std::optional<jid> from;
        std::optional<jid> to;

        void bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) override;
    };

}
