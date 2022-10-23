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
#include "plugin.hh"

#include "config/file.hh"
#include "config/section.hh"
#include "config/account.hh"
#include "config/option.hh"

namespace weechat
{
    class config;
    struct config_file;
    struct config_section;
    struct config_option;

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

        static std::optional<config> instance;

    public:
        static bool init();
        static bool read();
        static bool write();
    };
}
