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
#include "breadcrumb.hh"

using namespace std::placeholders;

namespace weechat
{
    struct config_file;
    struct config_section;

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
                            [](const void *data, void *, struct t_config_option *opt, const char *value) {
                                auto& option = *reinterpret_cast<config_option*>(const_cast<void*>(data));
                                if (option != opt) throw std::invalid_argument("option != opt");
                                if (!option.check_value) return 1;
                                return option.check_value(value) ? 1 : 0;
                            }, this, nullptr,
                            [](const void *data, void *, struct t_config_option *opt) {
                                auto& option = *reinterpret_cast<config_option*>(const_cast<void*>(data));
                                if (option != opt) throw std::invalid_argument("option != opt");
                                if (option.on_changed) option.on_changed();
                            }, this, nullptr,
                            [](const void *data, void *, struct t_config_option *opt) {
                                auto& option = *reinterpret_cast<config_option*>(const_cast<void*>(data));
                                if (option != opt) throw std::invalid_argument("option != opt");
                                if (option.on_deleted) option.on_deleted();
                            }, this, nullptr), section, name) {
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
}
