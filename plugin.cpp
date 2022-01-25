// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <csignal>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "config.hh"
#include "account.hh"
#include "connection.hh"
#include "command.hh"
#include "input.hh"
#include "buffer.hh"
#include "completion.hh"

struct t_weechat_plugin *weechat_xmpp_plugin = NULL;

struct t_hook *weechat_xmpp_process_timer = NULL;

struct t_gui_bar_item *weechat_xmpp_typing_bar_item = NULL;

#pragma GCC visibility push(default)
extern "C" {
WEECHAT_PLUGIN_NAME(WEECHAT_XMPP_PLUGIN_NAME);
WEECHAT_PLUGIN_DESCRIPTION(N_("XMPP client protocol"));
WEECHAT_PLUGIN_AUTHOR("bqv <weechat@fron.io>");
WEECHAT_PLUGIN_VERSION(WEECHAT_XMPP_PLUGIN_VERSION);
WEECHAT_PLUGIN_LICENSE("MPL2");
WEECHAT_PLUGIN_PRIORITY(5500);
}

extern "C"
void weechat_signal_handler(int)
{
    __asm__("int3");
}

extern "C"
int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    std::signal(SIGSEGV, weechat_signal_handler);

    weechat_xmpp_plugin = plugin;

    if (!config__init())
        return WEECHAT_RC_ERROR;

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

    return WEECHAT_RC_OK;
}

extern "C"
int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
    // make C compiler happy
    (void) plugin;

    if (weechat_xmpp_typing_bar_item)
        weechat_bar_item_remove(weechat_xmpp_typing_bar_item);

    if (weechat_xmpp_process_timer)
        weechat_unhook(weechat_xmpp_process_timer);

    config__write();

    account__disconnect_all();

    account__free_all();

    xmpp_shutdown();

    return WEECHAT_RC_OK;
}
