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

#include "weechat.hh"
#include "strophe.hh"

namespace weechat::xmpp {
    namespace xmpp = ::xmpp;

    class config {
    public:
        inline config() : config(config::default_name) {}
        explicit config(std::string name);

        enum class nick_completion
        {
            SMART_OFF = 0,
            SMART_SPEAKERS,
            SMART_SPEAKERS_HIGHLIGHTS,
        };

        struct option_data {
            std::string type;
            std::string description;
            std::string value;
            std::string range;
        };

        bool read();
        bool write();

        inline std::string& name() { return this->m_name; }

        inline weechat::config_file& file() { return this->m_file; }
        inline weechat::config_section& section_account() { return this->m_section_account; }
        inline weechat::config_section& section_account_default() { return this->m_section_account_default; }

        inline nick_completion look_nick_completion_smart() {
            int value = this->m_look_nick_completion_smart;
            return static_cast<nick_completion>(value);;
        }

        static inline const std::string default_name = "xmpp";

    private:
        std::string m_name;

        weechat::config_file m_file;

        weechat::config_section m_section_look;
        weechat::config_section m_section_account_default;
        weechat::config_section m_section_account;

        weechat::config_option m_look_nick_completion_smart;

        std::map<std::string, weechat::config_option> m_account_default;
    };
}
