// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <ctime>

#include "node.hh"
#pragma GCC visibility push(default)
#include "ns.hh"
#pragma GCC visibility pop

std::string stanza::uuid(xmpp_ctx_t *context) {
    std::shared_ptr<char> uuid {
        xmpp_uuid_gen(context),
        [=](auto x) { xmpp_free(context, x); }
    };
    return uuid.get();
}

std::string get_name(xmpp_stanza_t *stanza) {
    const char *result = NULL;
    result = xmpp_stanza_get_name(stanza);
    if (result)
        return result;
    else
        return {};
}

tl::optional<std::string> get_attribute(xmpp_stanza_t *stanza, const char *name) {
    const char *result = NULL;
    result = xmpp_stanza_get_attribute(stanza, name);
    if (result)
        return result;
    else
        return {};
}

std::string get_text(xmpp_stanza_t *stanza) {
    const char *result = NULL;
    result = xmpp_stanza_get_text_ptr(stanza);
    if (result)
        return result;
    else
        return {};
}

std::chrono::system_clock::time_point get_time(const std::string& text) {
    std::tm tm = {};
    if (strptime(text.data(), "%FT%T%z", &tm)) {
        throw std::invalid_argument("Bad time format");
    } else {
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }
}

const std::regex jid::pattern(
    "^((?:([^@/<>'\"]+)@)?([^@/<>'\"]+))(?:/([^<>'\"]*))?$");

jid::jid(xmpp_ctx_t *, std::string s) : full(s) {
    std::smatch match;

    if (std::regex_search(full, match, pattern))
    {
        auto as_sv = [&](std::ssub_match m) {
            if(!m.matched) return std::string_view();
            size_t offset = &*m.first - &*match[0].first;
            return std::string_view{full.data() + offset, static_cast<size_t>(m.length())};
        };

        bare = as_sv(match[1]);
        local = as_sv(match[2]);
        domain = as_sv(match[3]);
        resource = as_sv(match[4]);
    }
    else
    {
        bare = full;
        domain = bare;
    }
}

bool jid::is_bare() const {
    return !resource.empty();
}

xml::node::node() {}

void xml::node::bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) {
    name = get_name(stanza);

    id = get_attribute(stanza, "id");
    ns = get_attribute(stanza, "xmlns");

    int count = xmpp_stanza_get_attribute_count(stanza);
    std::vector<const char*> attrvec(count * 2, nullptr);
    const char **attrs = attrvec.data();
    xmpp_stanza_get_attributes(stanza, attrs, count * 2);
    for (int i = 0; i < count; i++) {
        const char *key = attrs[(2*i)];
        const char *value = attrs[(2*i)+1];
        attributes.emplace(key, value);
    }

    text = get_text(stanza);

    for (xmpp_stanza_t *child = xmpp_stanza_get_children(stanza);
            child; child = xmpp_stanza_get_next(child)) {
        if (xmpp_stanza_is_text(child))
            text += get_text(child);
        else
            children.emplace_back(context, child);
    }
}

void xml::message::bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) {
    auto result = get_attribute(stanza, "from");
    if (result)
        from = jid(context, *result);
    result = get_attribute(stanza, "to");
    if (result)
        to = jid(context, *result);
    type = get_attribute(stanza, "type");

    node::bind(context, stanza);
}

tl::optional<std::string> xml::presence::show() {
    auto child = get_children("show");
    if (child.size() > 0)
        return child.front().get().text;
    return {};
}

tl::optional<std::string> xml::presence::status() {
    auto child = get_children("status");
    if (child.size() > 0)
        return child.front().get().text;
    return {};
}

void xml::presence::bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) {
    auto result = get_attribute(stanza, "from");
    if (result)
        from = jid(context, *result);
    result = get_attribute(stanza, "to");
    if (result)
        to = jid(context, *result);
    type = get_attribute(stanza, "type");

    node::bind(context, stanza);
}

void xml::iq::bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) {
    auto result = get_attribute(stanza, "from");
    if (result)
        from = jid(context, *result);
    result = get_attribute(stanza, "to");
    if (result)
        to = jid(context, *result);
    type = get_attribute(stanza, "type");

    node::bind(context, stanza);
}

void xml::error::bind(xmpp_ctx_t *context, xmpp_stanza_t *stanza) {
    auto result = get_attribute(stanza, "from");
    if (result)
        from = jid(context, *result);
    result = get_attribute(stanza, "to");
    if (result)
        to = jid(context, *result);

    node::bind(context, stanza);
}
