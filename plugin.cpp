// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "plugin.hh"
#include "weechat.hh"
#include "strophe.hh"
#include "config.hh"
#include "account.hh"

#define WEECHAT_XMPP_PLUGIN_NAME "xmpp"
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.0"

namespace c {
    extern "C" {
#include "plugin.h"
// #include "connection.h"
        void connection__init();
// #include "command.h"
        void command__init();
// #include "input.h"
        int input__text_changed_cb(const void*, void*, const char*, const char*, void*);
// #include "buffer.h"
        std::string buffer__typing_bar_cb(weechat::gui_bar_item&, weechat::gui_window&,
                                          weechat::gui_buffer&, weechat::hashtable&);
// #include "completion.h"
        void completion__init();

        struct t_weechat_plugin *weechat_xmpp_plugin() {
            return (struct t_weechat_plugin*)&*weechat::globals::plugin;
        }
        const char *weechat_xmpp_plugin_name() {
            return WEECHAT_XMPP_PLUGIN_NAME;
        }
        const char *weechat_xmpp_plugin_version() {
            return WEECHAT_XMPP_PLUGIN_VERSION;
        }
    }
}

namespace weechat {
    plugin::plugin()
        // try not to think about it too hard
        : plugin(nullptr) {
    }

    plugin::plugin(struct t_weechat_plugin* plugin)
        : std::reference_wrapper<struct t_weechat_plugin>(*plugin) {
    }

    bool plugin::init(std::vector<std::string>) {
        if (!this->m_config.emplace().read())
        {
            weechat::printf(nullptr, "%s: Error during config init",
                            this->name());
            return false;
        }

        c::connection__init();

        c::command__init();

        c::completion__init();

        this->m_process_timer.emplace(plugin::timer_interval_sec * 1000, 0, 0,
                                      [](int) { return weechat::errc::ok; });

        if (!weechat::bar_search("typing"))
        {
            weechat::bar_new("typing", "off", "400", "window", "${typing}",
                             "bottom", "horizontal", "vertical",
                             "1", "1", "default", "default", "default", "default",
                             "off", "xmpp_typing");
        }

        this->m_typing_bar_item.emplace("xmpp_typing", weechat::gui_bar_item::build_callback());

        weechat::hook_signal("input_text_changed", &c::input__text_changed_cb);

        return true;
    }

    bool plugin::end() {
        this->m_typing_bar_item.reset();

        this->m_process_timer.reset();

        this->m_config->write();

        weechat::xmpp::account::disconnect_all();

        weechat::xmpp::globals::accounts.clear();

        ::xmpp::shutdown();

        return true;
    }

    std::string_view plugin::name() const {
        return plugin_get_name(*this);
    }

    weechat::xmpp::config& plugin::config() {
        return *this->m_config;
    }

    weechat::plugin globals::plugin;
}

extern "C" {
    WEECHAT_PLUGIN_NAME(WEECHAT_XMPP_PLUGIN_NAME)
    WEECHAT_PLUGIN_DESCRIPTION(N_("XMPP client protocol"))
    WEECHAT_PLUGIN_AUTHOR("bqv <weechat@fron.io>")
    WEECHAT_PLUGIN_VERSION(WEECHAT_XMPP_PLUGIN_VERSION)
    WEECHAT_PLUGIN_LICENSE("MPL2")
    WEECHAT_PLUGIN_PRIORITY(5500)

    weechat::errc weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
    {
        weechat::globals::plugin = (struct weechat::t_weechat_plugin*)plugin;
        std::vector<std::string> args(argv, argv+argc);
        return weechat::globals::plugin.init(args)
            ? weechat::ok : weechat::err;
    }

    weechat::errc weechat_plugin_end(struct t_weechat_plugin *)
    {
        return weechat::globals::plugin.end()
            ? weechat::ok : weechat::err;
    }
}
