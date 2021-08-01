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
            return (struct t_weechat_plugin*)weechat::globals::plugin;
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
        : std::reference_wrapper<weechat_plugin>(
            // try not to think about it too hard
            *(weechat_plugin*)nullptr) {
    }

    bool plugin::init(std::vector<std::string>) {
        if (!c::config__init())
        {
            weechat::printf(nullptr, "%s: Error during config init",
                            globals::plugin->name);
            return false;
        }

        c::config__read();

        c::connection__init();

        c::command__init();

        c::completion__init();

        globals::process_timer =
            weechat::hook_timer(plugin::timer_interval_sec * 1000, 0, 0,
                                &c::account__timer_cb, nullptr, nullptr);

        if (!weechat::bar_search("typing"))
        {
            weechat::bar_new("typing", "off", "400", "window", "${typing}",
                             "bottom", "horizontal", "vertical",
                             "1", "1", "default", "default", "default", "default",
                             "off", "xmpp_typing");
        }

        globals::typing_bar_item =
            weechat::bar_item_new("xmpp_typing",
                                  (char* (*)(const void*, void*,
                                             t_gui_bar_item*, t_gui_window*,
                                             t_gui_buffer*, t_hashtable*))(&c::buffer__typing_bar_cb),
                                  nullptr, nullptr);

        weechat::hook_signal("input_text_changed", &c::input__text_changed_cb, nullptr, nullptr);

        return true;
    }

    bool plugin::end() {
        if (globals::typing_bar_item)
            weechat::bar_item_remove(globals::typing_bar_item);

        if (globals::process_timer)
            weechat::unhook(globals::process_timer);

        c::config__write();

        c::account__disconnect_all();

        c::account__free_all();

        xmpp::shutdown();

        return true;
    }

    std::string_view plugin::name() const {
        return plugin_get_name(*this);
    }

    struct t_weechat_plugin* globals::plugin = nullptr;

    hook* globals::process_timer = nullptr;

    gui_bar_item* globals::typing_bar_item = nullptr;
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
        weechat::globals::plugin = (weechat::weechat_plugin*)plugin;
        std::vector<std::string> args(argv, argv+argc);
        return weechat::plugin::init(args) ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
    }

    weechat::rc weechat_plugin_end(struct t_weechat_plugin *)
    {
        return weechat::plugin::end() ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
    }
}
