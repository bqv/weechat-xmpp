// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <weechat/weechat-plugin.h>

#include "strophe.h"
#include "plugin.hh"
#include "account.hh"
#include "config.hh"

int account_read_cb(weechat::config_section& section,
                    const char *option_name, const char *value)
{
    if (!option_name)
        return WEECHAT_CONFIG_READ_MEMORY_ERROR;
    std::istringstream breadcrumbs(option_name);
    std::string account_name, option_id;
    std::getline(breadcrumbs, account_name, '.');
    std::getline(breadcrumbs, option_id, '.');
    if (account_name.empty())
        return WEECHAT_CONFIG_READ_MEMORY_ERROR;

    int rc = WEECHAT_CONFIG_READ_OK;
    weechat::account* account = nullptr;
    if (!weechat::account::search(account, account_name))
        account = &weechat::accounts.emplace(
            std::piecewise_construct, std::forward_as_tuple(account_name),
            std::forward_as_tuple(weechat::config::instance->file, account_name)).first->second;
    if (account)
    {
        auto options = {
            std::ref(account->option_jid),
            std::ref(account->option_password),
            std::ref(account->option_tls),
            std::ref(account->option_nickname),
            std::ref(account->option_autoconnect),
            std::ref(account->option_resource),
            std::ref(account->option_status),
            std::ref(account->option_pgp_path),
            std::ref(account->option_pgp_keyid),
        };

        if (!account->reloading_from_config++)
        {
            for (auto option : options)
                option.get().clear();
        }

        account->reloading_from_config %= options.size();

        if (option_id == "jid") rc |= (account->option_jid = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "password") rc |= (account->option_password = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "tls") rc |= (account->option_tls = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "nickname") rc |= (account->option_nickname = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "autoconnect") rc |= (account->option_autoconnect = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "resource") rc |= (account->option_resource = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "status") rc |= (account->option_status = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "pgp_path") rc |= (account->option_pgp_path = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;
        if (option_id == "pgp_keyid") rc |= (account->option_pgp_keyid = value) == WEECHAT_CONFIG_OPTION_SET_ERROR;

        if (!account->reloading_from_config)
        {
            bool ac_global = std::stoul(std::unique_ptr<char>(
                                            weechat_info_get("auto_connect", NULL)).get());
            bool ac_local = account->autoconnect();
            if (ac_local && ac_global)
                account->connect();
        }
    }
    else
    {
        weechat_printf(
            NULL,
            _("%s%s: error adding account \"%s\""),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            account_name.data());
    }

    if (rc != WEECHAT_CONFIG_READ_OK)
    {
        weechat_printf(
            NULL,
            _("%s%s: error creating account option \"%s\""),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, option_name);
    }
    return rc;
}

int account_write_cb(weechat::config_section& section, const char *section_name)
{
    if (!weechat_config_write_line(section.file, section_name, NULL))
        return WEECHAT_CONFIG_WRITE_ERROR;

    for (auto& account : weechat::accounts)
    {
        if (!account.second.write())
            return WEECHAT_CONFIG_WRITE_ERROR;
    }

    return WEECHAT_CONFIG_WRITE_OK;
}

int config_reload(weechat::config_file &file)
{
  //weechat_config_section_free_options(file.configuration.section_account_default);
  //weechat_config_section_free_options(file.configuration.section_account);
    weechat::accounts.clear();

    return weechat_config_reload(file);
}

bool weechat::config_account::write()
{
    if (!option_jid.write()) return false;
    if (!option_password.write()) return false;
    if (!option_tls.write()) return false;
    if (!option_nickname.write()) return false;
    if (!option_autoconnect.write()) return false;
    if (!option_resource.write()) return false;
    if (!option_status.write()) return false;
    if (!option_pgp_path.write()) return false;
    if (!option_pgp_keyid.write()) return false;
    return true;
}

weechat::config::config()
    : file{*this, "xmpp", &config_reload}
    , section_account_default{file, "account_default", 0, 0, {}, {}, {}, {}, {}}
    , section_account{file, "account", 0, 0, &account_read_cb, &account_write_cb, {}, {}, {}}
    , section_look{file, "look", 0, 0, {}, {}, {}, {}, {}}
    , account_default{file, section_account_default}
    , look{
            .nick_completion_smart{file, section_look, "nick_completion_smart", "integer",
                ("smart completion for nicks (completes first with last speakers): "
                 "speakers = all speakers (including highlights), "
                 "speakers_highlights = only speakers with highlight"),
                "off|speakers|speakers_highlights", 0, 0,
                "speakers", nullptr, false,
                {}, {}, {}}}
{
}

weechat::config::~config() {}

tl::optional<weechat::config> weechat::config::instance;

bool weechat::config::init() { instance.emplace(); return true; }
bool weechat::config::read() { return instance->file.read(); }
bool weechat::config::write() { return instance->file.read(); }
