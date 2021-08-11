// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "weechat.hh"
#include "plugin.hh"

using namespace std::placeholders;

namespace weechat {
    config_option::config_option(
        config_file& config_file, config_section& section, std::string name,
        std::string type, std::string description, std::string string_values,
        int min, int max, std::string default_value, std::string value, bool null_value_allowed,
        check_callback check_value_cb, change_callback change_cb, delete_callback delete_cb)
        : config_option(weechat::config_new_option(
                            config_file, section, name.data(), type.data(),
                            description.data(), string_values.data(), min, max,
                            default_value.data(), value.data(), null_value_allowed,
                            this->m_check_cb, this->m_change_cb, this->m_delete_cb)) {
        this->m_check_cb = check_value_cb;
        this->m_change_cb = change_cb;
        this->m_delete_cb = delete_cb;
        this->m_name = name;
    }

    config_option::config_option(struct t_config_option* option)
        : std::reference_wrapper<struct t_config_option>(*option) {
        if (!option)
            throw weechat::error("failed to create config option");
    }

    config_option::operator int () const {
        return weechat::config_integer(*this);
    }
    config_option::operator bool () const {
        return weechat::config_boolean(*this);
    }
    config_option::operator std::string () const {
        return weechat::config_string(*this);
    }
    std::string config_option::string(std::string property) const {
        return weechat::config_option_get_string(*this, property.data());
    }
    config_option& config_option::operator= (std::string_view value) {
        weechat::config_option_set(*this, std::string(value).data(), 1);
        return *this;
    }

    config_section::config_section(config_file& config_file, std::string name,
                                   bool user_can_add_options, bool user_can_delete_options,
                                   read_callback read_cb, write_callback write_cb,
                                   write_default_callback write_default_cb,
                                   create_option_callback create_option_cb,
                                   delete_option_callback delete_option_cb)
        : config_section(weechat::config_new_section(config_file, name.data(),
                                                     user_can_add_options, user_can_delete_options,
                                                     this->m_read_cb, this->m_write_cb,
                                                     this->m_write_default_cb,
                                                     this->m_create_option_cb,
                                                     this->m_delete_option_cb)) {
        this->m_read_cb = read_cb;
        this->m_write_cb = write_cb;
        this->m_write_default_cb = write_default_cb;
        this->m_create_option_cb = create_option_cb;
        this->m_delete_option_cb = delete_option_cb;
        this->m_name = name;
    }

    config_section::config_section(struct t_config_section* section)
        : std::reference_wrapper<struct t_config_section>(*section) {
        if (!section)
            throw weechat::error("failed to create config section");
    }

    config_file::config_file(std::string name, reload_callback reload_cb)
        : config_file(weechat::config_new(name.data(), this->m_reload_cb)) {
        this->m_reload_cb = reload_cb;
        this->m_name = name;
    }

    config_file::config_file(struct t_config_file* file)
        : std::reference_wrapper<struct t_config_file>(*file) {
        if (!file)
            throw weechat::error("failed to create config file");
    }

    gui_bar_item::gui_bar_item(std::string_view name, gui_bar_item::build_callback callback)
        : gui_bar_item(weechat::bar_item_new(name.data(), this->m_cb)) {
        this->m_cb = callback;
    }

    gui_buffer::gui_buffer(std::string name, gui_buffer::input_callback input_cb,
                           gui_buffer::close_callback close_cb)
        : gui_buffer(weechat::buffer_new(name.data(), this->m_input_cb, this->m_close_cb)) {
        this->m_input_cb = input_cb;
        this->m_close_cb = close_cb;
        this->name = name;
    }

    gui_buffer::gui_buffer(struct t_gui_buffer* buffer)
        : std::reference_wrapper<struct t_gui_buffer>(*buffer) {
        if (!buffer)
            throw weechat::error("failed to create buffer");
    }

    gui_buffer::~gui_buffer() {
        weechat::buffer_close(*this);
    }

    gui_bar_item::gui_bar_item(struct t_gui_bar_item* item)
        : std::reference_wrapper<struct t_gui_bar_item>(*item) {
        if (!item)
            throw weechat::error("failed to create bar item");
    }

    gui_bar_item::~gui_bar_item() {
        weechat::bar_item_remove(*this);
    }

    hook::hook(struct t_hook* hook)
        : std::reference_wrapper<struct t_hook>(*hook) {
        if (!hook)
            throw weechat::error("failed to create hook timer");
    }

    hook::hook(long interval, int align_second, int max_calls,
               hook::timer_callback callback)
        : hook(weechat::hook_timer(interval, align_second, max_calls,
                                   callback ? &this->m_timer_cb : nullptr)) {
        this->m_timer_cb = callback;
    }

    hook::~hook() {
        weechat::unhook(*this);
    }
}
