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

namespace weechat
{
    class config;
    struct config_section;

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
                          [](const void *data, void *, struct t_config_file *config_file) {
                              auto& file = *reinterpret_cast<struct config_file*>(const_cast<void*>(data));
                              if (file != config_file) throw std::invalid_argument("file != config_file");
                              if (!file.reload) return 1;
                              return file.reload() ? 1 : 0;
                              // WEECHAT_CONFIG_READ_OK == 0
                              // WEECHAT_CONFIG_READ_MEMORY_ERROR == -1
                              // WEECHAT_CONFIG_READ_FILE_NOT_FOUND == -2
                          }, this, nullptr), config, name) {
            this->reload = std::bind(cb_reload, std::ref(*this));
        }
        operator struct t_config_file *() { return get(); }
        std::function<int()> reload;
        config& configuration;
        std::unordered_map<struct t_config_section *, config_section&> sections;
        bool read() { return weechat_config_read(*this); }
        bool write() { return weechat_config_write(*this); }
    };
}
