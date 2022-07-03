// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <functional>
#include <unordered_map>
#include <tl/optional.hpp>
#include <weechat/weechat-plugin.h>
#include "fmt/core.h"
#include "plugin.hh"

using namespace std::placeholders;

namespace weechat
{
    enum class tls_policy
    {
        disable = 0,
        normal,
        trust,
    };

    class config;
    struct config_file;
    struct config_section;
    struct config_option;

    struct config_breadcrumb {
        config_breadcrumb(std::string name)
            : name(name), parent(tl::nullopt) {}

        config_breadcrumb(std::string name, config_breadcrumb& parent)
            : name(name), parent(parent) {}

        std::string name;
        tl::optional<config_breadcrumb&> parent;
    };

    struct config_free { void operator() (struct t_config_file *ptr) { weechat_config_free(ptr); } };
    struct config_file : public std::unique_ptr<struct t_config_file, config_free>, public config_breadcrumb {
        config_file(struct t_config_file *ptr, config& config, std::string name)
            : std::unique_ptr<struct t_config_file, config_free>(ptr)
            , config_breadcrumb(name)
            , configuration(config) {
            if (ptr == nullptr) throw std::runtime_error("weechat_config_new");
        }
        config_file(config& config, std::string name, std::function<int(config_file&)> cb_reload)
            : config_file(weechat_config_new(
                          name.data(),
                          [](const void *, void *data, struct t_config_file *config_file) {
                              auto& file = *reinterpret_cast<struct config_file*>(data);
                              if (file != config_file) throw std::invalid_argument("file != config_file");
                              if (!file.reload) return 1;
                              return file.reload() ? 1 : 0;
                              // WEECHAT_CONFIG_READ_OK == 0
                              // WEECHAT_CONFIG_READ_MEMORY_ERROR == -1
                              // WEECHAT_CONFIG_READ_FILE_NOT_FOUND == -2
                          }, nullptr, this), config, name) {
            this->reload = std::bind(cb_reload, std::ref(*this));
        }
        operator struct t_config_file *() { return get(); }
        std::function<int()> reload;
        config& configuration;
        std::unordered_map<struct t_config_section *, config_section&> sections;
        bool read() { return weechat_config_read(*this); }
        bool write() { return weechat_config_write(*this); }
    };

    struct config_section_free { void operator() (struct t_config_section *ptr) { weechat_config_section_free(ptr); } };
    struct config_section : public std::unique_ptr<struct t_config_section, config_section_free>, public config_breadcrumb {
        config_section(struct t_config_section *ptr, config_file& file, std::string name)
            : std::unique_ptr<struct t_config_section, config_section_free>(ptr)
            , config_breadcrumb(name)
            , file(file) {
            if (ptr == nullptr) throw std::runtime_error("weechat_config_new_section");
        }
        config_section(config_file& config_file, std::string name,
                       bool user_can_add_options, bool user_can_delete_options,
                       std::function<bool(config_section&, const char *, const char *)> cb_read,
                       std::function<bool(config_section&, const char *)> cb_write,
                       std::function<bool(config_section&, const char *)> cb_write_default,
                       std::function<bool(config_section&, const char *, const char *)> cb_create_option,
                       std::function<bool(config_section&, config_option &)> cb_delete_option)
        : config_section(weechat_config_new_section(
                             config_file, name.data(), user_can_add_options, user_can_delete_options,
                             [](const void *, void *data, struct t_config_file *config_file,
                                struct t_config_section *sect, const char *option_name, const char *value) {
                                 auto& section = *reinterpret_cast<config_section*>(data);
                                 if (section != sect) throw std::invalid_argument("section != sect");
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.read) return 1;
                                 return section.read(option_name, value) ? 2 : 0;
                                 /// dev manual indicates:
                                 // WEECHAT_CONFIG_READ_OK == 0
                                 // WEECHAT_CONFIG_READ_MEMORY_ERROR == -1
                                 // WEECHAT_CONFIG_READ_FILE_NOT_FOUND == -2
                                 /// code indicates:
                                 // WEECHAT_CONFIG_OPTION_SET_OK_CHANGED == 2
                                 // WEECHAT_CONFIG_OPTION_SET_OK_SAME_VALUE == 1
                                 // WEECHAT_CONFIG_OPTION_SET_ERROR == 0
                                 // WEECHAT_CONFIG_OPTION_SET_OPTION_NOT_FOUND == -1
                             }, nullptr, this,
                             [](const void *, void *data, struct t_config_file *config_file,
                                const char *section_name) {
                                 auto& section = *reinterpret_cast<config_section*>(data);
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.write) return 0;
                                 return section.write(section_name) ? 0 : -1;
                                 // WEECHAT_CONFIG_WRITE_OK == 0
                                 // WEECHAT_CONFIG_WRITE_ERROR == -1
                                 // WEECHAT_CONFIG_WRITE_FILE_NOT_FOUND == -2
                             }, nullptr, this,
                             [](const void *, void *data, struct t_config_file *config_file,
                                const char *section_name) {
                                 auto& section = *reinterpret_cast<config_section*>(data);
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.write_default) return 0;
                                 return section.write_default(section_name) ? 0 : -1;
                                 // WEECHAT_CONFIG_WRITE_OK == 0
                                 // WEECHAT_CONFIG_WRITE_ERROR == -1
                                 // WEECHAT_CONFIG_WRITE_FILE_NOT_FOUND == -2
                             }, nullptr, this,
                             [](const void *, void *data, struct t_config_file *config_file,
                                struct t_config_section *sect, const char *option_name, const char *value) {
                                 auto& section = *reinterpret_cast<config_section*>(data);
                                 if (section != sect) throw std::invalid_argument("section != sect");
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.create_option) return 1;
                                 return section.create_option(option_name, value) ? 2 : 0;
                                 // WEECHAT_CONFIG_OPTION_SET_OK_CHANGED == 2
                                 // WEECHAT_CONFIG_OPTION_SET_OK_SAME_VALUE == 1
                                 // WEECHAT_CONFIG_OPTION_SET_ERROR == 0
                                 // WEECHAT_CONFIG_OPTION_SET_OPTION_NOT_FOUND == -1
                             }, nullptr, this,
                             [](const void *, void *data, struct t_config_file *config_file,
                                struct t_config_section *sect, struct t_config_option *opt) {
                                 auto& section = *reinterpret_cast<config_section*>(data);
                                 if (section != sect) throw std::invalid_argument("section != sect");
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.delete_option) return 0;
                                 auto option = section.options.find(opt);
                                 if (option == section.options.end()) throw std::invalid_argument("unknown option");
                                 return section.delete_option(option->second) ? 1 : -1;
                                 // WEECHAT_CONFIG_OPTION_UNSET_OK_NO_RESET == 0
                                 // WEECHAT_CONFIG_OPTION_UNSET_OK_RESET == 1
                                 // WEECHAT_CONFIG_OPTION_UNSET_OK_REMOVED == 2
                                 // WEECHAT_CONFIG_OPTION_UNSET_ERROR == -1
                             }, nullptr, this), config_file, name) {
            if (cb_read)
                this->read = std::bind(cb_read, std::ref(*this), _1, _2);
            if (cb_write)
                this->write = std::bind(cb_write, std::ref(*this), _1);
            if (cb_write_default)
                this->write_default = std::bind(cb_write_default, std::ref(*this), _1);
            if (cb_create_option)
                this->create_option = std::bind(cb_create_option, std::ref(*this), _1, _2);
            if (cb_delete_option)
                this->delete_option = std::bind(cb_delete_option, std::ref(*this), _1);
        }
        operator struct t_config_section *() { return get(); }
        std::function<bool(const char *, const char *)> read;
        std::function<bool(const char *)> write;
        std::function<bool(const char *)> write_default;
        std::function<bool(const char *, const char *)> create_option;
        std::function<bool(config_option&)> delete_option;
        config_file& file;
        std::unordered_map<struct t_config_option *, config_option&> options;
    };

    struct config_option_free { void operator() (struct t_config_option *ptr) { weechat_config_option_free(ptr); } };
    struct config_option : public std::unique_ptr<struct t_config_option, config_option_free>, public config_breadcrumb {
        config_option(struct t_config_option *ptr, config_section& section, std::string name)
            : std::unique_ptr<struct t_config_option, config_option_free>(ptr)
            , config_breadcrumb(name, section)
            , section(section) {
            if (ptr == nullptr) throw std::runtime_error("weechat_config_new_option");
        }
        config_option(config_file& config_file, config_section& section,
                      std::string name, const char *type, const char *description, const char *string_values,
                      int min, int max, const char *default_value, const char *value, bool null_value_allowed,
                      std::function<bool(config_option&, const char *)> cb_check_value,
                      std::function<void(config_option&)> cb_change,
                      std::function<void(config_option&)> cb_delete)
        : config_option(weechat_config_new_option(
                            config_file, section,
                            name.data(), type, description, string_values,
                            min, max, default_value, value, null_value_allowed,
                            [](const void *, void *data, struct t_config_option *opt, const char *value) {
                                auto& option = *reinterpret_cast<config_option*>(data);
                                if (option != opt) throw std::invalid_argument("option != opt");
                                if (!option.check_value) return 1;
                                return option.check_value(value) ? 1 : 0;
                            }, nullptr, this,
                            [](const void *, void *data, struct t_config_option *opt) {
                                auto& option = *reinterpret_cast<config_option*>(data);
                                if (option != opt) throw std::invalid_argument("option != opt");
                                if (option.on_changed) option.on_changed();
                            }, nullptr, this,
                            [](const void *, void *data, struct t_config_option *opt) {
                                auto& option = *reinterpret_cast<config_option*>(data);
                                if (option != opt) throw std::invalid_argument("option != opt");
                                if (option.on_deleted) option.on_deleted();
                            }, nullptr, this), section, name) {
            if (cb_check_value)
                this->check_value = std::bind(cb_check_value, std::ref(*this), _1);
            if (cb_change)
                this->on_changed = std::bind(cb_change, std::ref(*this));
            if (cb_delete)
                this->on_deleted = std::bind(cb_delete, std::ref(*this));
        }
        operator struct t_config_option *() { return get(); }
        std::function<bool(const char *)> check_value;
        std::function<void()> on_changed;
        std::function<void()> on_deleted;
        config_section& section;
        int operator =(std::string value) { return weechat_config_option_set(*this, value.data(), 1); }
        int clear() { return weechat_config_option_set(*this, nullptr, 1); }
        std::string_view string() { return weechat_config_string(*this); }
        int integer() { return weechat_config_integer(*this); }
        bool boolean() { return weechat_config_boolean(*this); }
        bool write() { return weechat_config_write_option(section.file, *this); }
    };

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

    class config {
    public:
        enum class nick_completion
        {
            SMART_OFF = 0,
            SMART_SPEAKERS,
            SMART_SPEAKERS_HIGHLIGHTS,
        };

        config_file file;

        config_section section_account_default;
        config_section section_account;
        config_section section_look;

        config_account account_default;
        struct {
            config_option nick_completion_smart;
        } look;

    public:
        config();
        ~config();

        static tl::optional<config> instance;

    public:
        static bool init();
        static bool read();
        static bool write();
    };
}
