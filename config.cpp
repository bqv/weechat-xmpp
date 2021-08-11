// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "config.hh"
#include "plugin.hh"
#include "account.hh"

weechat::xmpp::config::config(std::string name)
    : m_name(name)
    , m_file(weechat::config_file(name, std::function(
                                      [](weechat::config_file& file) {
                                          return weechat::xmpp::account::reload(file);
                                      })))
    , m_section_look(weechat::config_section(
        this->m_file, "look", false, false, {}, {}, {}, {}, {}))
    , m_section_account_default(weechat::config_section(
        this->m_file, "account_default", false, false, {}, {}, {}, {}, {}))
    , m_section_account(weechat::config_section(
        this->m_file, "account", false, false,
        &weechat::xmpp::account::read_cb,
        &weechat::xmpp::account::write_cb,
        {}, {}, {}))
    , m_look_nick_completion_smart(weechat::config_option(
        this->m_file, this->m_section_look,
        "nick_completion_smart", "integer",
        weechat::gettext("smart completion for nicks (completes first with last speakers): "
                         "speakers = all speakers (including highlights), "
                         "speakers_highlights = only speakers with highlight"),
        "off|speakers|speakers_highlights", 0, 0, "speakers", "", false,
        {}, {}, {})) {
    weechat::xmpp::account::init_defaults(this->m_file, this->m_section_account_default);
}

bool weechat::xmpp::config::read()
{
    return weechat::config_read(this->m_file) == weechat::ok;
}

bool weechat::xmpp::config::write()
{
    return weechat::config_write(this->m_file) == weechat::ok;
}
