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
    class config;
    struct config_file;
    struct config_section;
    struct config_option;

    struct config_section_free { void operator() (struct t_config_section *ptr) {  weechat_config_section_free(ptr); } };
    struct config_section : public std::unique_ptr<struct t_config_section, config_section_free>, public config_breadcrumb {
        config_section(struct t_config_section *ptr, config_file& file, std::string name)
            : std::unique_ptr<struct t_config_section, config_section_free>(ptr)
            , config_breadcrumb(name)
            , file(file) {
            if (ptr == nullptr) throw std::runtime_error("weechat_config_new_section");
        }
        config_section(config_file& config_file, std::string name,
                       bool user_can_add_options, bool user_can_delete_options,
                       std::function<bool(config_section&, const char *, const char *)> cb_read,
                       std::function<bool(config_section&, const char *)> cb_write,
                       std::function<bool(config_section&, const char *)> cb_write_default,
                       std::function<bool(config_section&, const char *, const char *)> cb_create_option,
                       std::function<bool(config_section&, config_option &)> cb_delete_option)
        : config_section(weechat_config_new_section(
                             config_file, name.data(), user_can_add_options, user_can_delete_options,
                             [](const void *data, void *, struct t_config_file *config_file,
                                struct t_config_section *sect, const char *option_name, const char *value) {
                                 auto& section = *reinterpret_cast<config_section*>(const_cast<void*>(data));
                                 if (section != sect) throw std::invalid_argument("section != sect");
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.read) return 1;
                                 return section.read(option_name, value) ? 2 : 0;
                                 /// dev manual indicates:
                                 // WEECHAT_CONFIG_READ_OK == 0
                                 // WEECHAT_CONFIG_READ_MEMORY_ERROR == -1
                                 // WEECHAT_CONFIG_READ_FILE_NOT_FOUND == -2
                                 /// code indicates:
                                 // WEECHAT_CONFIG_OPTION_SET_OK_CHANGED == 2
                                 // WEECHAT_CONFIG_OPTION_SET_OK_SAME_VALUE == 1
                                 // WEECHAT_CONFIG_OPTION_SET_ERROR == 0
                                 // WEECHAT_CONFIG_OPTION_SET_OPTION_NOT_FOUND == -1
                             }, this, nullptr,
                             [](const void *data, void *, struct t_config_file *config_file,
                                const char *section_name) {
                                 auto& section = *reinterpret_cast<config_section*>(const_cast<void*>(data));
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.write) return 0;
                                 return section.write(section_name) ? 0 : -1;
                                 // WEECHAT_CONFIG_WRITE_OK == 0
                                 // WEECHAT_CONFIG_WRITE_ERROR == -1
                                 // WEECHAT_CONFIG_WRITE_FILE_NOT_FOUND == -2
                             }, this, nullptr,
                             [](const void *data, void *, struct t_config_file *config_file,
                                const char *section_name) {
                                 auto& section = *reinterpret_cast<config_section*>(const_cast<void*>(data));
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.write_default) return 0;
                                 return section.write_default(section_name) ? 0 : -1;
                                 // WEECHAT_CONFIG_WRITE_OK == 0
                                 // WEECHAT_CONFIG_WRITE_ERROR == -1
                                 // WEECHAT_CONFIG_WRITE_FILE_NOT_FOUND == -2
                             }, this, nullptr,
                             [](const void *data, void *, struct t_config_file *config_file,
                                struct t_config_section *sect, const char *option_name, const char *value) {
                                 auto& section = *reinterpret_cast<config_section*>(const_cast<void*>(data));
                                 if (section != sect) throw std::invalid_argument("section != sect");
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.create_option) return 1;
                                 return section.create_option(option_name, value) ? 2 : 0;
                                 // WEECHAT_CONFIG_OPTION_SET_OK_CHANGED == 2
                                 // WEECHAT_CONFIG_OPTION_SET_OK_SAME_VALUE == 1
                                 // WEECHAT_CONFIG_OPTION_SET_ERROR == 0
                                 // WEECHAT_CONFIG_OPTION_SET_OPTION_NOT_FOUND == -1
                             }, this, nullptr,
                             [](const void *data, void *, struct t_config_file *config_file,
                                struct t_config_section *sect, struct t_config_option *opt) {
                                 auto& section = *reinterpret_cast<config_section*>(const_cast<void*>(data));
                                 if (section != sect) throw std::invalid_argument("section != sect");
                                 if (section.file != config_file) throw std::invalid_argument("section.file != config_file");
                                 if (!section.delete_option) return 0;
                                 auto option = section.options.find(opt);
                                 if (option == section.options.end()) throw std::invalid_argument("unknown option");
                                 return section.delete_option(option->second) ? 1 : -1;
                                 // WEECHAT_CONFIG_OPTION_UNSET_OK_NO_RESET == 0
                                 // WEECHAT_CONFIG_OPTION_UNSET_OK_RESET == 1
                                 // WEECHAT_CONFIG_OPTION_UNSET_OK_REMOVED == 2
                                 // WEECHAT_CONFIG_OPTION_UNSET_ERROR == -1
                             }, this, nullptr), config_file, name) {
            if (cb_read)
                this->read = std::bind(cb_read, std::ref(*this), _1, _2);
            if (cb_write)
                this->write = std::bind(cb_write, std::ref(*this), _1);
            if (cb_write_default)
                this->write_default = std::bind(cb_write_default, std::ref(*this), _1);
            if (cb_create_option)
                this->create_option = std::bind(cb_create_option, std::ref(*this), _1, _2);
            if (cb_delete_option)
                this->delete_option = std::bind(cb_delete_option, std::ref(*this), _1);
        }
        operator struct t_config_section *() { return get(); }
        std::function<bool(const char *, const char *)> read;
        std::function<bool(const char *)> write;
        std::function<bool(const char *)> write_default;
        std::function<bool(const char *, const char *)> create_option;
        std::function<bool(config_option&)> delete_option;
        config_file& file;
        std::unordered_map<struct t_config_option *, config_option&> options;
    };
}
