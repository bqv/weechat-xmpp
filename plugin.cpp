// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "plugin.hh"

#define WEECHAT_XMPP_PLUGIN_NAME "xmpp"
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.0"

namespace c {
    extern "C" {
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strophe.h>

#include "plugin.h"
#include "config.h"
#include "account.h"
#include "connection.h"
#include "command.h"
#include "input.h"
#include "buffer.h"
#include "completion.h"

        struct t_weechat_plugin *weechat_xmpp_plugin() {
            return weechat_plugin;
        };
        const char *weechat_xmpp_plugin_name() {
            return weechat::plugin::instance.name().data();
        };
        const char *weechat_xmpp_plugin_version() {
            return weechat::plugin::instance.version().data();
        };
    }

#define TIMER_INTERVAL_SEC 0.01

    struct t_hook *weechat_xmpp_process_timer = NULL;

    struct t_gui_bar_item *weechat_xmpp_typing_bar_item = NULL;

    bool weechat_plugin_init()
    {
        if (!config__init())
            return false;

        config__read();

        connection__init();

        command__init();

        completion__init();

        weechat_xmpp_process_timer = weechat_hook_timer(TIMER_INTERVAL_SEC * 1000, 0, 0,
                &account__timer_cb,
                NULL, NULL);

        if (!weechat_bar_search("typing"))
        {
            weechat_bar_new("typing", "off", "400", "window", "${typing}",
                    "bottom", "horizontal", "vertical",
                    "1", "1", "default", "default", "default", "default",
                    "off", "xmpp_typing");
        }

        weechat_xmpp_typing_bar_item = weechat_bar_item_new("xmpp_typing",
                &buffer__typing_bar_cb,
                NULL, NULL);

        weechat_hook_signal("input_text_changed", &input__text_changed_cb, NULL, NULL);

        return true;
    }

    void weechat_plugin_end()
    {
        if (weechat_xmpp_typing_bar_item)
            weechat_bar_item_remove(weechat_xmpp_typing_bar_item);

        if (weechat_xmpp_process_timer)
            weechat_unhook(weechat_xmpp_process_timer);

        config__write();

        account__disconnect_all();

        account__free_all();

        xmpp_shutdown();
    }
}

namespace weechat {
    plugin::plugin() {
    }

    plugin::plugin(plugin_ptr ptr)
        : plugin_ptr(std::move(ptr)) {
        this->m_name = WEECHAT_XMPP_PLUGIN_NAME;
        this->m_version = WEECHAT_XMPP_PLUGIN_VERSION;
    }

    plugin::plugin(struct t_weechat_plugin *ptr)
        : plugin(std::move(weechat::plugin_ptr(
            ptr, [this] (struct t_weechat_plugin *) { }
        ))) {
    }

    bool plugin::init(std::vector<std::string>) {
        weechat_printf(nullptr, "%s: It works!", this->name().data());
        return c::weechat_plugin_init();
    }

    bool plugin::end() {
        c::weechat_plugin_end();
        return true;
    }

    plugin plugin::instance;
}

extern "C" {
    WEECHAT_PLUGIN_NAME(WEECHAT_XMPP_PLUGIN_NAME);
    WEECHAT_PLUGIN_DESCRIPTION(N_("XMPP client protocol"));
    WEECHAT_PLUGIN_AUTHOR("bqv <weechat@fron.io>");
    WEECHAT_PLUGIN_VERSION(WEECHAT_XMPP_PLUGIN_VERSION);
    WEECHAT_PLUGIN_LICENSE("MPL2");
    WEECHAT_PLUGIN_PRIORITY(5500);

    int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
    {
        weechat::plugin::instance = std::move(weechat::plugin(plugin));
        std::vector<std::string> args(argv, argv+argc);
        return weechat::plugin::instance.init(args) ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
    }

    int weechat_plugin_end(struct t_weechat_plugin *)
    {
        return weechat::plugin::instance.end() ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
    }
}
