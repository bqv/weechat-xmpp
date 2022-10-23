// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <functional>
#include <unordered_map>
#include <optional>
#include <weechat/weechat-plugin.h>
#include "fmt/core.h"
#include "../plugin.hh"
#include "section.hh"
#include "option.hh"

namespace weechat
{
    enum class tls_policy
    {
        disable = 0,
        normal,
        trust,
    };

    struct config_file;
    struct config_section;
    struct config_option;

    class config_account {
    public:
        config_account(config_file& config_file, config_section& section_account, const char *name)
            : section(section_account)
            , option_jid(config_file, section_account,
                         fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "jid"),
                         "string", "XMPP Account JID", nullptr, 0, 0, "", "", false,
                         [&](config_option&, const char *) { return true; },
                         [&](config_option&) {},
                         [&](config_option&) {})
            , option_password(config_file, section_account,
                              fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "password"),
                              "string", "XMPP Account Password", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_tls(config_file, section_account,
                         fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "tls"),
                         "integer", "XMPP Server TLS Policy", "disable|normal|trust", 0, 0,
                         "normal", "normal", false,
                         [&](config_option&, const char *) { return true; },
                         [&](config_option&) {},
                         [&](config_option&) {})
            , option_nickname(config_file, section_account,
                              fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "nickname"),
                              "string", "XMPP Account Nickname", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_autoconnect(config_file, section_account,
                                 fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "autoconnect"),
                                 "boolean", "Autoconnect XMPP Account", nullptr, 0, 0, "", "", false,
                                 [&](config_option&, const char *) { return true; },
                                 [&](config_option&) {},
                                 [&](config_option&) {})
            , option_resource(config_file, section_account,
                              fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "resource"),
                              "string", "XMPP Account Resource", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_status(config_file, section_account,
                            fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "status"),
                            "string", "XMPP Account Login Status", nullptr, 0, 0,
                            "probably about to segfault", "probably about to segfault", false,
                            [&](config_option&, const char *) { return true; },
                            [&](config_option&) {},
                            [&](config_option&) {})
            , option_pgp_path(config_file, section_account,
                              fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "pgp_path"),
                              "string", "XMPP Account PGP Keyring Dir", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_pgp_keyid(config_file, section_account,
                               fmt::format("{0}.{1} << xmpp.account_default.{1}", name, "pgp_keyid"),
                               "string", "XMPP Account PGP Key ID", nullptr, 0, 0, "", "", false,
                               [&](config_option&, const char *) { return true; },
                               [&](config_option&) {},
                               [&](config_option&) {})
        {
        }

        config_account(config_file& config_file, config_section& section_account_default)
            : section(section_account_default)
            , option_jid(config_file, section_account_default,
                         "jid", "string", "XMPP Account JID", nullptr, 0, 0, "", "", false,
                         [&](config_option&, const char *) { return true; },
                         [&](config_option&) {},
                         [&](config_option&) {})
            , option_password(config_file, section_account_default,
                              "password", "string", "XMPP Account Password", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_tls(config_file, section_account_default,
                         "tls", "integer", "XMPP Server TLS Policy", "disable|normal|trust", 0, 0,
                         "normal", "normal", false,
                         [&](config_option&, const char *) { return true; },
                         [&](config_option&) {},
                         [&](config_option&) {})
            , option_nickname(config_file, section_account_default,
                              "nickname", "string", "XMPP Account Nickname", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_autoconnect(config_file, section_account_default,
                                 "autoconnect", "boolean", "Autoconnect XMPP Account", nullptr, 0, 0, "", "", false,
                                 [&](config_option&, const char *) { return true; },
                                 [&](config_option&) {},
                                 [&](config_option&) {})
            , option_resource(config_file, section_account_default,
                              "resource", "string", "XMPP Account Resource", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_status(config_file, section_account_default,
                            "status", "string", "XMPP Account Login Status", nullptr, 0, 0,
                            "probably about to segfault", "probably about to segfault", false,
                            [&](config_option&, const char *) { return true; },
                            [&](config_option&) {},
                            [&](config_option&) {})
            , option_pgp_path(config_file, section_account_default,
                              "pgp_path", "string", "XMPP Account PGP Keyring Dir", nullptr, 0, 0, "", "", false,
                              [&](config_option&, const char *) { return true; },
                              [&](config_option&) {},
                              [&](config_option&) {})
            , option_pgp_keyid(config_file, section_account_default,
                               "pgp_keyid", "string", "XMPP Account PGP Key ID", nullptr, 0, 0, "", "", false,
                               [&](config_option&, const char *) { return true; },
                               [&](config_option&) {},
                               [&](config_option&) {})
        {
        }

        config_section& section;

        config_option option_jid;
        config_option option_password;
        config_option option_tls;
        config_option option_nickname;
        config_option option_autoconnect;
        config_option option_resource;
        config_option option_status;
        config_option option_pgp_path;
        config_option option_pgp_keyid;

        bool read(const char *, const char *);
        bool write();
    };
}
