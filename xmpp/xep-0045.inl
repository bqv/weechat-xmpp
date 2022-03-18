// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <fmt/core.h>

#include "node.hh"
#pragma GCC visibility push(default)
#include "ns.hh"
#pragma GCC visibility pop

namespace xml {

    /* Multi-User Chat */
    class xep0045 : virtual public node {
    public:
        enum class affiliation {
            admin,
            member,
            none,
            outcast,
            owner,
        };

        enum class role {
            moderator,
            none,
            participant,
            visitor,
        };

        static affiliation parse_affiliation(std::string_view s) {
            if (s == "admin")
                return affiliation::admin;
            else if (s == "member")
                return affiliation::member;
            else if (s == "none")
                return affiliation::none;
            else if (s == "outcast")
                return affiliation::outcast;
            else if (s == "owner")
                return affiliation::owner;
            throw std::invalid_argument(
                fmt::format("Bad affiliation: {}", s));
        }

        static std::string_view format_affiliation(affiliation e) {
            switch (e) {
            case affiliation::admin:
                return "admin";
            case affiliation::member:
                return "member";
            case affiliation::none:
                return "none";
            case affiliation::outcast:
                return "outcast";
            case affiliation::owner:
                return "owner";
            default:
                return "";
            }
        }

        static role parse_role(std::string_view s) {
            if (s == "moderator")
                return role::moderator;
            else if (s == "none")
                return role::none;
            else if (s == "participant")
                return role::participant;
            else if (s == "visitor")
                return role::visitor;
            throw std::invalid_argument(
                fmt::format("Bad role: {}", s));
        }

        static std::string_view format_role(role e) {
            switch (e) {
            case role::moderator:
                return "moderator";
            case role::none:
                return "none";
            case role::participant:
                return "participant";
            case role::visitor:
                return "visitor";
            default:
                return "";
            }
        }

        class x {
        private:
            struct decline {
                decline(node& node) {
                    for (auto& child : node.get_children("reason"))
                        reason += child.get().text;
                    if (auto attr = node.get_attr("from"))
                        from = jid(node.context, *attr);
                    if (auto attr = node.get_attr("to"))
                        to = jid(node.context, *attr);
                };

                std::string reason;
                std::optional<jid> from;
                std::optional<jid> to;
            };

            struct destroy {
                destroy(node& node) {
                    for (auto& child : node.get_children("reason"))
                        reason += child.get().text;
                    if (auto attr = node.get_attr("target"))
                        target = jid(node.context, *attr);
                };

                std::string reason;
                std::optional<jid> target;
            };

            struct invite {
                invite(node& node) {
                    for (auto& child : node.get_children("reason"))
                        reason += child.get().text;
                    if (auto attr = node.get_attr("from"))
                        from = jid(node.context, *attr);
                    if (auto attr = node.get_attr("to"))
                        to = jid(node.context, *attr);
                };

                std::string reason;
                std::optional<jid> from;
                std::optional<jid> to;
            };

            class item {
            private:
                struct actor {
                    actor(node& node) {
                        for (auto& child : node.get_children("reason"))
                            reason += child.get().text;
                        if (auto attr = node.get_attr("jid"))
                            target = jid(node.context, *attr);
                        if (auto attr = node.get_attr("nick"))
                            nick = *attr;
                    }

                    std::string reason;
                    std::optional<jid> target;
                    std::string nick;
                };

                struct continue_ {
                    continue_(node& node) {
                        if (auto attr = node.get_attr("thread"))
                            thread = *attr;
                    }

                    std::string thread;
                };

            public:
                item(node& node) {
                    for (auto& child : node.get_children("actor"))
                        actors.emplace_back(child);
                    for (auto& child : node.get_children("continue"))
                        continues.emplace_back(child);
                    for (auto& child : node.get_children("reason"))
                        reason += child.get().text;
                    if (auto attr = node.get_attr("affiliation"))
                        affiliation = parse_affiliation(*attr);
                    if (auto attr = node.get_attr("jid"))
                        target = jid(node.context, *attr);
                    if (auto attr = node.get_attr("nick"))
                        nick = *attr;
                    if (auto attr = node.get_attr("role"))
                        role = parse_role(*attr);
                };

                std::vector<actor> actors;
                std::vector<continue_> continues;
                std::string reason;
                std::optional<enum affiliation> affiliation;
                std::optional<jid> target;
                std::optional<std::string> nick;
                std::optional<enum role> role;
            };

        public:
            x(node& node) {
                for (auto& child : node.get_children("decline"))
                    declines.emplace_back(child);
                for (auto& child : node.get_children("destroy"))
                    destroys.emplace_back(child);
                for (auto& child : node.get_children("invite"))
                    invites.emplace_back(child);
                for (auto& child : node.get_children("item"))
                    items.emplace_back(child);
                for (auto& child : node.get_children("password"))
                    passwords.emplace_back(child.get().text);
                for (auto& child : node.get_children("status"))
                    if (auto code = child.get().get_attr("code"))
                        statuses.push_back(std::stoi(*code));
            }

            std::vector<decline> declines;
            std::vector<destroy> destroys;
            std::vector<invite> invites;
            std::vector<item> items;
            std::vector<std::string> passwords;
            std::vector<int> statuses;
        };

        class error { // THIS IS RFC 6120 :(
        private:
            enum condition {
                not_authorized,
                registration_required,
                forbidden,
                not_allowed,
                not_acceptable,
                conflict,
                service_unavailable,
                item_not_found
            };

            enum class action {
                auth,
                cancel,
                continue_,
                modify,
                wait
            };

            static action parse_action(std::string_view s) {
                if (s == "auth")
                    return action::auth;
                else if (s == "cancel")
                    return action::cancel;
                else if (s == "continue")
                    return action::continue_;
                else if (s == "modify")
                    return action::modify;
                else if (s == "wait")
                    return action::wait;
                throw std::invalid_argument(
                    fmt::format("Bad action: {}", s));
            }

            static std::string_view format_action(action e) {
                switch (e) {
                case action::auth:
                    return "auth";
                case action::cancel:
                    return "cancel";
                case action::continue_:
                    return "continue";
                case action::modify:
                    return "modify";
                case action::wait:
                    return "wait";
                default:
                    return "";
                }
            }

        public:
            error(node& node) {
                if (auto attr = node.get_attr("by"))
                    by = jid(node.context, *attr);
                if (auto attr = node.get_attr("type"))
                    type = parse_action(*attr);

                using xmpp_stanzas = urn::ietf::params::xml::ns::xmpp_stanzas;

                for (auto& child : node.get_children<xmpp_stanzas>("not-authorized"))
                    condition = not_authorized;
                for (auto& child : node.get_children<xmpp_stanzas>("forbidden"))
                    condition = forbidden;
                for (auto& child : node.get_children<xmpp_stanzas>("item-not-found"))
                    condition = item_not_found;
                for (auto& child : node.get_children<xmpp_stanzas>("not-allowed"))
                    condition = not_allowed;
                for (auto& child : node.get_children<xmpp_stanzas>("not-acceptable"))
                    condition = not_acceptable;
                for (auto& child : node.get_children<xmpp_stanzas>("registration-required"))
                    condition = registration_required;
                for (auto& child : node.get_children<xmpp_stanzas>("conflict"))
                    condition = conflict;
                for (auto& child : node.get_children<xmpp_stanzas>("service-unavailable"))
                    condition = service_unavailable;

                for (auto& child : node.get_children("text"))
                    description = child.get().text;
            }

            std::optional<jid> by;
            std::optional<enum action> type;
            std::optional<enum condition> condition;
            std::optional<std::string> description;

            const char* reason() {
                if (condition)
                    switch (*condition)
                    {
                      case not_authorized:
                        return "Password Required";
                      case forbidden:
                        return "Banned";
                      case item_not_found:
                        return "No such MUC";
                      case not_allowed:
                        return "MUC Creation Failed";
                      case not_acceptable:
                        return "Unacceptable Nickname";
                      case registration_required:
                        return "Not on Member List";
                      case conflict:
                        return "Nickname Conflict";
                      case service_unavailable:
                        return "Service Unavailable (MUC Full?)";
                    }
                return "Unspecified";
            }
        };

    private:
        std::optional<bool> _muc;
        std::optional<std::optional<x>> _muc_user;
        std::optional<std::optional<error>> _error;
    public:
        bool muc() {
            if (!_muc)
            {
                auto child = get_children<jabber_org::protocol::muc>("x");
                _muc = child.size() > 0;
            }
            return *_muc;
        }

        std::optional<x>& muc_user() {
            if (!_muc_user)
            {
                auto child = get_children<jabber_org::protocol::muc::user>("x");
                if (child.size() > 0)
                    _muc_user = child.front().get();
                else
                    _muc_user.emplace(std::nullopt);
            }
            return *_muc_user;
        }

        std::optional<error>& error() {
            if (!_error)
            {
                auto child = get_children("error");
                if (child.size() > 0)
                    _error = child.front().get();
                else
                    _error.emplace(std::nullopt);
            }
            return *_error;
        }
    };

}
