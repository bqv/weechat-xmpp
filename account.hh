// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <functional>
#include <optional>
#include <map>
#include <ctime>

#include "plugin.hh"
#include "strophe.hh"
#include "config.hh"

namespace weechat::xmpp {
    namespace xmpp = ::xmpp;

    class account {
    public:
        explicit account(std::string name);

        struct option_data {
            std::string type;
            std::string description;
            std::string value;
            std::string range;
        };

        struct device
        {
            int id;
            std::string name;
        };

        struct mam_query
        {
            std::string id;
            std::string with;
            std::optional<std::time_t> start;
            std::optional<std::time_t> end;
        };

        std::string name;

        bool ready;
        bool active;

        int current_retry;
        int reconnect_delay;
        std::time_t reconnect_start;

        xmpp::context context;
        xmpp::connection connection;

        weechat::gui_buffer buffer;

        struct t_omemo *omemo;
        struct t_pgp *pgp;

        std::map<int, device> devices;
        std::map<std::string, mam_query> mam_queries;
        std::map<std::string, struct t_user*> users;
        std::map<std::string, struct t_channel*> channels;

        inline std::string jid() {
            return this->connection && xmpp_conn_is_connected(this->connection)
                ? xmpp_jid_bare(this->context,
                                xmpp_conn_get_bound_jid(this->connection))
                : weechat::config_string(this->m_options.at("jid"));
        }
        inline std::string jid_device() {
            return this->connection && xmpp_conn_is_connected(this->connection)
                ? xmpp_conn_get_bound_jid(this->connection)
                : xmpp_jid_new(this->context,
                               xmpp_jid_node(
                                   this->context,
                                   weechat::config_string(
                                       this->m_options.at("jid"))),
                               xmpp_jid_domain(
                                   this->context,
                                   weechat::config_string(
                                       this->m_options.at("jid"))),
                               "weechat");
        }
        inline weechat::config_option password() {
            return weechat::config_option(this->m_options.at("password"));
        }
        inline weechat::config_option tls() {
            return weechat::config_option(this->m_options.at("tls"));
        }
        inline weechat::config_option nickname() {
            return weechat::config_option(this->m_options.at("nickname"));
        }
        inline weechat::config_option autoconnect() {
            return weechat::config_option(this->m_options.at("autoconnect"));
        }
        inline weechat::config_option resource() {
            return weechat::config_option(this->m_options.at("resource"));
        }
        inline weechat::config_option status() {
            return weechat::config_option(this->m_options.at("status"));
        }
        inline weechat::config_option pgp_pubring_path() {
            return weechat::config_option(this->m_options.at("pgp_pubring_path"));
        }
        inline weechat::config_option pgp_secring_path() {
            return weechat::config_option(this->m_options.at("pgp_secring_path"));
        }
        inline weechat::config_option pgp_keyid() {
            return weechat::config_option(this->m_options.at("pgp_keyid"));
        }

        bool connected();
        void disconnect(bool reconnect);
        weechat::gui_buffer create_buffer();
        void close_connection();
        bool connect();
        bool timer_cb(int remaining_calls);

        static void disconnect_all();

        static std::pair<std::map<std::string, account>::iterator, bool> create(std::string name);

        static void init_defaults(config_file& config_file, config_section& section);
        static bool reload(config_file& config_file);
        static int read_cb(config_file& config_file, config_section& section,
                           std::string option_name, std::string value);
        static int write_cb(config_file& config_file, std::string section_name);
        static void change_cb(config_option& option);

    private:
        std::map<std::string, weechat::config_option> m_options;

        static std::map<std::string, weechat::config_option> m_default_options;
        static std::map<std::string, config::option_data> m_option_defaults;

        friend class weechat::xmpp::config;
    };

    namespace globals {
        extern std::map<std::string, account> accounts;
    }
}
