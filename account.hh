// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <ctime>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>

#include "fmt/core.h"
#include "strophe.h"
#include "pgp.hh"
#include "omemo.hh"
#include "config.hh"
#include "channel.hh"
#include "connection.hh"
#include "user.hh"

namespace weechat
{
    class channel;
    class user;

    void log_emit(void *const userdata, const xmpp_log_level_t level,
                  const char *const area, const char *const msg);

    class account : public config_account
    {
    public:
        struct device
        {
            std::uint32_t id;
            std::string name;
            std::string label;
        };

        struct mam_query
        {
            std::string id;
            std::string with;
            std::optional<time_t> start;
            std::optional<time_t> end;
        };

    public:
        bool disconnected = false;

        std::unordered_map<std::uint32_t, device> devices;
        std::unordered_map<std::string, mam_query> mam_queries;

    private:
        bool is_connected = false;

        int current_retry = 0;
        int reconnect_delay = 0;
        int reconnect_start = 0;

        xmpp_mem_t memory = { nullptr };
        xmpp_log_t logger = { nullptr };

        std::string buffer_as_string;

        friend void log_emit(void *const userdata, const xmpp_log_level_t level,
                             const char *const area, const char *const msg);

    public:
        std::string name;
        weechat::xmpp::pgp pgp;
        weechat::xmpp::omemo omemo;
        libstrophe::context context;
        weechat::connection connection;
        struct t_gui_buffer *buffer = nullptr;
        std::unordered_map<std::string, weechat::channel> channels;
        std::unordered_map<std::string, weechat::user> users;

        std::unordered_map<std::string, struct t_config_option *> options;

        int reloading_from_config = 0;

    public:
        account(config_file& config_file, const std::string name);
        ~account();

        static bool search(account* &out,
                           const std::string name, bool casesensitive = false);
        static int timer_cb(const void *pointer, void *data, int remaining_calls);
        static void disconnect_all();

        bool connected() { return is_connected; }

        bool search_device(device* out, std::uint32_t id);
        void add_device(device *device);
        void device_free_all();
        xmpp_stanza_t *get_devicelist();

        void add_mam_query(const std::string id, const std::string with,
                           std::optional<time_t> start, std::optional<time_t> end);
        bool mam_query_search(mam_query* out, const std::string id);
        void mam_query_remove(const std::string id);
        void mam_query_free_all();

        struct t_gui_buffer* create_buffer();

        void disconnect(int reconnect);
        void reset();
        int connect();

        std::string_view jid() {
            if (connection && xmpp_conn_is_connected(connection))
                return xmpp_jid_bare(context, xmpp_conn_get_bound_jid(connection));
            else
                return this->option_jid.string();
        }
        void jid(std::string jid) { this->option_jid = jid; }
        std::string_view jid_device() {
            if (connection && xmpp_conn_is_connected(connection))
                return xmpp_conn_get_bound_jid(connection);
            else
                return xmpp_jid_new(context,
                                    xmpp_jid_node(context, this->option_jid.string().data()),
                                    xmpp_jid_domain(context, this->option_jid.string().data()),
                                    "weechat");
        }
        std::string_view password() { return this->option_password.string(); }
        void password(std::string password) { this->option_password = password; }
        tls_policy tls() { return static_cast<tls_policy>(this->option_tls.integer()); }
        void tls(tls_policy tls) { this->option_tls = fmt::format("%d", static_cast<int>(tls)); }
        void tls(std::string tls) { this->option_tls = tls; }
        std::string_view nickname() { return this->option_nickname.string(); }
        void nickname(std::string nickname) { this->option_nickname = nickname; }
        bool autoconnect() { return this->option_autoconnect.boolean(); }
        void autoconnect(bool autoconnect) { this->option_autoconnect = autoconnect ? "on" : "off"; }
        void autoconnect(std::string autoconnect) { this->option_autoconnect = autoconnect; }
        std::string_view resource() { return this->option_resource.string(); }
        void resource(std::string resource) { this->option_resource = resource; }
        std::string_view status() { return this->option_status.string(); }
        void status(std::string status) { this->option_status = status; }
        std::string_view pgp_path() { return this->option_pgp_path.string(); }
        void pgp_path(std::string pgp_path) { this->option_pgp_path = pgp_path; }
        std::string_view pgp_keyid() { return this->option_pgp_keyid.string(); }
        void pgp_keyid(std::string pgp_keyid) { this->option_pgp_keyid = pgp_keyid; }
    };

    extern std::unordered_map<std::string, account> accounts;
}
