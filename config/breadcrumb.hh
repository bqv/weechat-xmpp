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

namespace weechat
{
    struct config_breadcrumb {
        config_breadcrumb(std::string name)
            : name(name), parent(std::nullopt) {}

        config_breadcrumb(std::string name, config_breadcrumb& parent)
            : name(name), parent(parent) {}

        std::string name;
        std::optional<std::reference_wrapper<config_breadcrumb>> parent;
    };
}
