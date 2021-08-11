// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include <stdio.h>
// #include <assert.h>
#include <sstream>

#include "account.hh"
#include "weechat.hh"
#include "strophe.hh"
#include "strophe.ipp"
#include "config.hh"

// #include "plugin.h"
// #include "input.h"
// #include "omemo.h"
// #include "connection.h"
// #include "user.h"
// #include "channel.h"
// #include "buffer.h"
#include "stubs.cpp"

std::map<std::string, weechat::xmpp::account> weechat::xmpp::globals::accounts;

std::map<std::string, weechat::config_option> weechat::xmpp::account::m_default_options;
std::map<std::string, weechat::xmpp::config::option_data> weechat::xmpp::account::m_option_defaults {
    { "jid", {"string", "XMPP Account JID", "", ""} },
    { "password", {"string", "XMPP Account Password", "", ""} },
    { "tls", {"integer", "XMPP Server TLS Policy", "normal", "disable|normal|trust"} },
    { "nickname", {"string", "XMPP Account Nickname", "", ""} },
    { "autoconnect", {"boolean", "Autoconnect XMPP Account", "", ""} },
    { "resource", {"string", "XMPP Account Resource", "", ""} },
    { "status", {"string", "XMPP Account Login Status", "probably about to segfault", ""} },
    { "pgp_pubring_path", {"string", "XMPP Account PGP Public Keyring Path",
                "${weechat_data_dir}/pubring.gpg", ""} },
    { "pgp_secring_path", {"string", "XMPP Account PGP Secure Keyring Path",
                "${weechat_data_dir}/secring.gpg", ""} },
    { "pgp_keyid", {"string", "XMPP Account PGP Key ID", "", ""} },
};

template xmpp::context::context(weechat::xmpp::account&);

template<>
void xmpp::logger<weechat::xmpp::account>::emit_weechat(
    weechat::xmpp::account& account, const level level,
    std::string_view area, std::string_view msg)
{
    using logger = xmpp::logger<weechat::xmpp::account>;

    const char *tags = level > logger::debug ? "no_log" : nullptr;

    std::string_view xml;
    if (std::size_t xmlpos = msg.find('<'); (level == logger::debug) &&
        (xmlpos != msg.npos))
    {
        xml = msg.substr(xmlpos);

        auto nullfd = std::unique_ptr<FILE, decltype(std::fclose)*>{
            std::fopen("/dev/null", "w+"),
            std::fclose
        };
        xml::set_error_context<FILE>(&*nullfd);

        std::string_view header = msg.substr(0, xmlpos);
        xml::document doc(xml);
        if (!doc) {
            weechat::printf(account.buffer,
                "xml: Error parsing the xml document");
            return;
        }
        const char *colour = weechat::color("blue");
        if (auto root = doc.root())
        {
            std::string tag = root->name();
            if (tag == "message")
            {
                colour = weechat::color("green");
            }
            else if (tag == "presence")
            {
                colour = weechat::color("yellow");
            }
            else if (tag == "iq")
            {
                colour = weechat::color("red");
            }
        }
        std::string formatted = doc.format();
        if (formatted.empty()) {
            weechat::printf(account.buffer,
                "xml: Error formatting the xml document");
            return;
        }
        int size = 0;
        auto lines = std::unique_ptr<char*[],
                                     decltype(weechat::string_free_split)*>{
            weechat::string_split(formatted.data(), "\r\n", nullptr, 0, 0, &size),
            weechat::string_free_split
        };
        if (lines[size-1][0] == 0)
            lines[--size] = 0;
        weechat::printf_date_tags(account.buffer, 0, tags,
            weechat::gettext("%s%s (%s): %s"),
            weechat::prefix("network"), area,
            level.name(), header);
        for (int i = 1; i < size; i++)
            weechat::printf_date_tags(account.buffer, 0, tags,
                weechat::gettext("%s%s"),
                colour, lines[i]);
    }
    else
    {
        weechat::printf_date_tags(account.buffer, 0, tags,
            weechat::gettext("%s%s (%s): %s"),
            weechat::prefix("network"), area,
            level.name(), msg);
    }
}

weechat::xmpp::account::account(std::string name)
    : context(*this)
    , connection(this->context)
    , buffer(name, {}, {})
{
    this->name = name;

    this->ready = false;
    this->active = false;

    this->current_retry = 0;
    this->reconnect_delay = 0;
    this->reconnect_start = 0;

    this->omemo = nullptr;
    this->pgp = nullptr;

    for (auto it = this->m_option_defaults.begin(); it != this->m_option_defaults.end(); it++)
    {
        std::string option_name = this->name + '.' + it->first
            + " << xmpp.account_default." + it->first;

        auto [option, success] = this->m_options.try_emplace(it->first,
            weechat::globals::plugin.config().file(),
            weechat::globals::plugin.config().section_account(),
            option_name, it->second.type,
            weechat::gettext(it->second.description.data()),
            it->second.range, 0, 0, it->second.value, it->second.value, false,
            std::function([this](weechat::config_option&, std::string){ return true; }),
            std::function([this](weechat::config_option&){ }),
            std::function([this](weechat::config_option&){ }));
        if (!success)
            throw weechat::error("duplicate option key");
        //option.change_cb(it->first, nullptr, this->m_options[it->first]);
    }
}

bool weechat::xmpp::account::connected()
{
    return xmpp::xmpp_conn_is_connected(this->connection);
}

void weechat::xmpp::account::disconnect(bool reconnect)
{
    if (this->connected())
    {
        /*
         * remove all nicks and write disconnection message on each
         * channel/private buffer
         */
        c::user__free_all(*this);
        weechat::nicklist_remove_all(this->buffer);
        for (auto& [name, channel] : this->channels)
        {
            weechat::nicklist_remove_all(channel->buffer);
            weechat::printf(channel->buffer,
                weechat::gettext("%s%s: disconnected from account"),
                weechat::prefix("network"), weechat::globals::plugin.name());
        }
        /* remove away status on account buffer */
        //weechat::buffer_set(this->buffer, "localvar_del_away", "");
    }

    this->close_connection();

    if (this->buffer)
    {
        weechat::printf(this->buffer,
            weechat::gettext("%s%s: disconnected from account"),
            weechat::prefix("network"), weechat::globals::plugin.name());
    }

    if (reconnect)
    {
        if (this->current_retry++ == 0)
        {
            this->reconnect_delay = 5;
            this->reconnect_start = time(nullptr) + this->reconnect_delay;
        }
        this->current_retry %= 5;
    }
    else
    {
        this->current_retry = 0;
        this->reconnect_delay = 0;
        this->reconnect_start = 0;
    }

    this->active = reconnect;

    /* send signal "account_disconnected" with account name */
    weechat::hook_signal_send<char*>("xmpp_account_disconnected",
                                     WEECHAT_HOOK_SIGNAL_STRING, this->name.data());
}

weechat::gui_buffer weechat::xmpp::account::create_buffer()
{
    std::string name = "account." + this->name;
    this->buffer = weechat::gui_buffer(name.data(),
                                       weechat::gui_buffer::input_callback(),
                                       weechat::gui_buffer::close_callback());
    if (!this->buffer)
        throw weechat::error("failed to create account buffer");

    if (!weechat::buffer_get_integer(this->buffer, "short_name_is_set"))
        weechat::buffer_set(this->buffer, "short_name", this->name.data());
    weechat::buffer_set(this->buffer, "localvar_set_type", "server");
    weechat::buffer_set(this->buffer, "localvar_set_server", this->name.data());
    weechat::buffer_set(this->buffer, "localvar_set_channel", this->name.data());
    std::string charset_modifier = "account." + this->name;
    weechat::buffer_set(this->buffer, "localvar_set_charset_modifier",
                        charset_modifier.data());
    weechat::buffer_set(this->buffer, "title", this->name.data());

    weechat::buffer_set(this->buffer, "nicklist", "1");
    weechat::buffer_set(this->buffer, "nicklist_display_groups", "0");
    weechat::buffer_set_pointer(this->buffer, "nicklist_callback",
                                reinterpret_cast<void*>(static_cast<void (*)(
                                    const void*, void*, weechat::t_gui_buffer*,
                                    const char*, const char*)>(
                                        [](const void *pointer, void*,
                                           struct t_gui_buffer *buffer,
                                           const char *nick1, const char *nick2) {
                                            auto& account = *reinterpret_cast<
                                                const weechat::xmpp::account*>(pointer);
                                            (void) account;
                                            c::buffer__nickcmp_cb((c::t_gui_buffer*)buffer,
                                                                  nick1, nick2);
                                        })));
    weechat::buffer_set_pointer(this->buffer, "nicklist_callback_pointer",
                                this);

    return this->buffer;
}

void weechat::xmpp::account::close_connection()
{
    if (this->connection)
    {
        if (xmpp::xmpp_conn_is_connected(this->connection))
            xmpp::xmpp_disconnect(this->connection);
    }
}

bool weechat::xmpp::account::connect()
{
    if (!this->buffer)
    {
        if (!this->create_buffer())
            return false;
        weechat::buffer_set(this->buffer, "display", "auto");
    }

    this->close_connection();

    c::connection__connect(*this, this->connection, this->jid(),
                           this->password(), this->tls());

    weechat::hook_signal_send("xmpp_account_connecting",
                              WEECHAT_HOOK_SIGNAL_STRING, this->name.data());

    return true;
}

bool weechat::xmpp::account::timer_cb(int)
{
    for (auto& [name, account] : weechat::xmpp::globals::accounts)
    {
        if (xmpp_conn_is_connecting(account.connection)
            || xmpp_conn_is_connected(account.connection))
            c::connection__process(account.context, account.connection, 10);
        else if (account.active && account.reconnect_start > 0
                 && account.reconnect_start < time(nullptr))
        {
            account.connect();
        }
    }

    return true;
}

void weechat::xmpp::account::disconnect_all()
{
    for (auto it = weechat::xmpp::globals::accounts.begin();
         it != weechat::xmpp::globals::accounts.end(); it++)
    {
        it->second.disconnect(false);
    }
}

std::pair<std::map<std::string, weechat::xmpp::account>::iterator, bool>
weechat::xmpp::account::create(std::string name)
{
    return weechat::xmpp::globals::accounts.try_emplace(name, name);
}

void weechat::xmpp::account::init_defaults(config_file& config_file, config_section& section)
{
    for (auto& [name, option_data] : weechat::xmpp::account::m_option_defaults)
    {
        weechat::xmpp::account::m_default_options.try_emplace(name,
            weechat::config_option(
                config_file, section, name,
                option_data.type, option_data.description, option_data.range,
                0, 0, option_data.value, option_data.value, true, {}, {}, {})).first->second;
    }
}

bool weechat::xmpp::account::reload(config_file&)
{
    for (auto& [_, account] : weechat::xmpp::globals::accounts)
        account.ready = false;

    if (!weechat::config_reload(weechat::globals::plugin.config().file()))
        return false;

    for (auto& [_, account] : weechat::xmpp::globals::accounts)
    {
        account.ready = true;

        std::string ac_global = weechat::info_get("auto_connect", nullptr);
        bool ac_local = account.autoconnect();
        if (ac_local && ac_global == "1")
            account.connect();
    }

    return true;
}

int weechat::xmpp::account::read_cb(config_file& config_file, config_section& section,
                                    std::string option_name, std::string value)
{
    int rc = WEECHAT_CONFIG_OPTION_SET_ERROR;

    if (!option_name.empty())
    {
        if (std::size_t pos_option = option_name.find('.');
            pos_option != option_name.npos)
        {
            std::string account_name = option_name.substr(0, pos_option);
            std::string option_id = option_name.substr(++pos_option);
            auto data_it = weechat::xmpp::account::m_option_defaults.find(option_id);
            if (data_it == weechat::xmpp::account::m_option_defaults.end())
            {
                rc = WEECHAT_CONFIG_OPTION_SET_OPTION_NOT_FOUND;
                return rc;
            }
            auto& option_data = data_it->second;

            if (account_name == "account_default")

            {
                auto& option =
                    weechat::xmpp::account::m_default_options.try_emplace(option_id,
                        weechat::config_option(
                            config_file, section, option_id,
                            option_data.type, option_data.description, option_data.range,
                            0, 0, option_data.value, option_data.value, true, {}, {}, {})).first->second;

                rc = weechat::config_option_set(option, value.data(), true);
                return rc;
            }

            const auto& item = weechat::xmpp::account::create(account_name).first;
            weechat::xmpp::account& account = item->second;

            auto& option = account.m_options.try_emplace(option_id,
                weechat::config_option(
                    config_file, section, option_id,
                    option_data.type, option_data.description, option_data.range,
                    0, 0, option_data.value, option_data.value, true, {}, {}, {})).first->second;

            rc = weechat::config_option_set(option, value.data(), true);
        }
    }

    if (rc == WEECHAT_CONFIG_OPTION_SET_ERROR)
    {
        weechat::printf(nullptr,
                        weechat::gettext("%s%s: error creating account option \"%s\""),
                        weechat::prefix("error"), weechat::globals::plugin.name().data(),
                        option_name);
    }

    return rc;
}

int weechat::xmpp::account::write_cb(config_file& config_file, std::string section_name)
{
    if (!weechat::config_write_line(config_file, section_name.data(), nullptr))
        return WEECHAT_CONFIG_WRITE_ERROR;

    for (auto& [_, account] : weechat::xmpp::globals::accounts)
    {
        for (auto& [name, option] : account.m_options)
        {
            if (!weechat::config_write_option(config_file, option))
                return WEECHAT_CONFIG_WRITE_ERROR;
        }
    }

    return WEECHAT_CONFIG_WRITE_OK;
}

void weechat::xmpp::account::change_cb(config_option& option)
{
    std::string name = option.string("name");
    std::string value = option.string("value");

    int split_num;
    char **split = weechat::string_split(name.data(), ".", nullptr, 0, 2, &split_num);
    auto it = weechat::xmpp::globals::accounts.find(split[0]);
    if (split_num >= 2 && it != weechat::xmpp::globals::accounts.end())
    {
        std::string key = split[1];

        (void) key;
        (void) value;
    }

    weechat::string_free_split(split);
}
