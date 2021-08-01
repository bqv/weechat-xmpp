// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "plugin.hh"
#include "strophe.hh"

#define WEECHAT_XMPP_PLUGIN_NAME "xmpp"
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.0"

namespace c {
    extern "C" {
#include "plugin.h"
#include "config.h"
#include "account.h"
#include "connection.h"
#include "command.h"
#include "input.h"
#include "buffer.h"
#include "completion.h"

        struct t_weechat_plugin *weechat_xmpp_plugin() {
            return (struct t_weechat_plugin*)&*weechat::globals::plugin;
        };
        const char *weechat_xmpp_plugin_name() {
            return WEECHAT_XMPP_PLUGIN_NAME;
        };
        const char *weechat_xmpp_plugin_version() {
            return WEECHAT_XMPP_PLUGIN_VERSION;
        };
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
        if (!c::config__init())
        {
            weechat::printf(nullptr, "%s: Error during config init",
                            this->name());
            return false;
        }

        c::config__read();

        c::connection__init();

        c::command__init();

        c::completion__init();

        this->m_process_timer =
            weechat::hook_timer(plugin::timer_interval_sec * 1000, 0, 0,
                                &c::account__timer_cb);

        if (!weechat::bar_search("typing"))
        {
            weechat::bar_new("typing", "off", "400", "window", "${typing}",
                             "bottom", "horizontal", "vertical",
                             "1", "1", "default", "default", "default", "default",
                             "off", "xmpp_typing");
        }

        this->m_typing_bar_item =
            weechat::bar_item_new("xmpp_typing",
                                  (char* (*)(const void*, void*,
                                             t_gui_bar_item*, t_gui_window*,
                                             t_gui_buffer*, t_hashtable*))(
                                                 &c::buffer__typing_bar_cb));

        weechat::hook_signal("input_text_changed", &c::input__text_changed_cb);

        return true;
    }

    bool plugin::end() {
        this->m_typing_bar_item.reset();

        this->m_process_timer.reset();

        c::config__write();

        c::account__disconnect_all();

        c::account__free_all();

        xmpp::shutdown();

        return true;
    }

    std::string_view plugin::name() const {
        return plugin_get_name(*this);
    }

    weechat::plugin globals::plugin;

    hook::hook(struct t_hook* hook)
        : std::reference_wrapper<struct t_hook>(*hook) {
    }

    hook::~hook() {
        weechat::unhook(*this);
    }

    gui_bar_item::gui_bar_item(struct t_gui_bar_item* item)
        : std::reference_wrapper<struct t_gui_bar_item>(*item) {
    }

    gui_bar_item::~gui_bar_item() {
        weechat::bar_item_remove(*this);
    }
}

extern "C" {
    WEECHAT_PLUGIN_NAME(WEECHAT_XMPP_PLUGIN_NAME);
    WEECHAT_PLUGIN_DESCRIPTION(N_("XMPP client protocol"));
    WEECHAT_PLUGIN_AUTHOR("bqv <weechat@fron.io>");
    WEECHAT_PLUGIN_VERSION(WEECHAT_XMPP_PLUGIN_VERSION);
    WEECHAT_PLUGIN_LICENSE("MPL2");
    WEECHAT_PLUGIN_PRIORITY(5500);

    weechat::rc weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
    {
        weechat::globals::plugin = (struct weechat::t_weechat_plugin*)plugin;
        std::vector<std::string> args(argv, argv+argc);
        return weechat::globals::plugin.init(args)
            ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
    }

    weechat::rc weechat_plugin_end(struct t_weechat_plugin *)
    {
        return weechat::globals::plugin.end()
            ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
    }
}
