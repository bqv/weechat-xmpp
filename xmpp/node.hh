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
#include <variant>
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

    std::string bare;
    std::string local;
    std::string domain;
    std::string resource;

    bool is_bare() const;
};

class xmlns;

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

        template<typename X, std::enable_if_t<std::is_base_of<xmlns,X>::value, int> = 0>
        inline std::vector<std::reference_wrapper<node>>
        get_children(std::string_view name) {
            std::vector<std::reference_wrapper<node>> list;
            std::copy_if(children.begin(), children.end(),
                         std::back_inserter(list),
                         [&](node& x) {
                             return x.name == name
                                 && x.ns == std::string_view(X());
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

namespace stanza {
    template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };

    extern std::string uuid(xmpp_ctx_t *context);

    class spec {
    protected:
        explicit spec(std::string_view tag): tag(tag) {}

        void child(spec& ch) {
            children.push_back(ch);
        }

        void attr(std::string k, std::string_view v) {
            attributes[k] = v;
        }

        void text(std::string_view s) {
            children.push_back(std::string(s));
        }

        template<typename X, std::enable_if_t<std::is_base_of<xmlns,X>::value, int> = 0>
        void xmlns() {
            attr("xmlns", X().ns());
        }

    private:
        const std::string tag;
        std::map<std::string, std::string> attributes;
        std::vector<std::variant<spec, std::string>> children;

    public:
        std::shared_ptr<xmpp_stanza_t> build(xmpp_ctx_t *context) {
            auto stanza = xmpp_stanza_new(context);
            xmpp_stanza_set_name(stanza, tag.data());
            for (auto& at : attributes) {
                xmpp_stanza_set_attribute(stanza, at.first.data(), at.second.data());
            }
            for (auto& ch : children) {
                std::visit(overloaded {
                    [&](spec& child) {
                        xmpp_stanza_add_child(stanza, child.build(context).get());
                    },
                    [&](std::string s) {
                        auto child = xmpp_stanza_new(context);
                        xmpp_stanza_set_text(child, s.data());
                        xmpp_stanza_add_child(stanza, child);
                        xmpp_stanza_release(child);
                    }
                }, ch);
            }
            return { stanza, &xmpp_stanza_release };
        }
    };
};

#include "xep-0027.inl"
#include "xep-0030.inl"
#include "xep-0045.inl"
#include "xep-0049.inl"
#include "xep-0115.inl"
#include "xep-0280.inl"
#include "xep-0319.inl"

namespace stanza {
    struct body : virtual public spec {
        body() : body("") {}
        body(std::string_view s) : spec("body") {
            text(s);
        }
    };

    struct message : virtual public spec {
        message() : spec("message") {}

        message& id(std::string_view s) { attr("id", s); return *this; }
        message& from(std::string_view s) { attr("from", s); return *this; }
        message& to(std::string_view s) { attr("to", s); return *this; }
        message& type(std::string_view s) { attr("type", s); return *this; }

        message& body(stanza::body b) { child(b); return *this; }
        message& body(std::string_view s) { return body(stanza::body(s)); }
    };

    struct presence : virtual public spec {
        presence() : spec("presence") {}

        presence& id(std::string_view s) { attr("id", s); return *this; }
        presence& from(std::string_view s) { attr("from", s); return *this; }
        presence& to(std::string_view s) { attr("to", s); return *this; }
        presence& lang(std::string_view s) { attr("lang", s); return *this; }
    };

    struct iq : virtual public spec,
                public xep0030::iq,
                public xep0049::iq,
                public xep0280::iq {
        iq() : spec("iq") {}

        iq& id(std::string_view s) { attr("id", s); return *this; }
        iq& from(std::string_view s) { attr("from", s); return *this; }
        iq& to(std::string_view s) { attr("to", s); return *this; }
        iq& type(std::string_view s) { attr("type", s); return *this; }
    };

    struct error : virtual public spec {
        error() : spec("error") {}
    };
}

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
