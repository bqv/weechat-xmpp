// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strophe.h>
#include <json.h>

#include "weechat/weechat-plugin.h"
#include "xmpp.h"
//#include "slack-config.h"
//#include "slack-command.h"
//#include "slack-workspace.h"
//#include "slack-api.h"
//#include "slack-buffer.h"
//#include "slack-completion.h"


WEECHAT_PLUGIN_NAME(XMPP_PLUGIN_NAME);
WEECHAT_PLUGIN_DESCRIPTION(N_("XMPP protocol"));
WEECHAT_PLUGIN_AUTHOR("bqv <weechat@fron.io>");
WEECHAT_PLUGIN_VERSION(XMPP_PLUGIN_VERSION);
WEECHAT_PLUGIN_LICENSE("MPL2");
WEECHAT_PLUGIN_PRIORITY(5500);

struct t_weechat_plugin *weechat_xmpp_plugin = NULL;

struct t_hook *xmpp_hook_timer = NULL;

struct t_gui_bar_item *xmpp_typing_bar_item = NULL;

void xmpp_lwsl_emit_weechat(int level, const char *line)
{
    char buf[50];
  //lwsl_timestamp(level, buf, sizeof(buf));

    weechat_printf(
        NULL,
        _("%s%s: %s%s"),
        weechat_prefix("error"), XMPP_PLUGIN_NAME,
        buf, line);
}

int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
	(void) argc;
	(void) argv;

    weechat_plugin = plugin;

  //lws_set_log_level(LLL_ERR | LLL_WARN /*| LLL_NOTICE | LLL_INFO | LLL_DEBUG
  //        | LLL_PARSER | LLL_HEADER | LLL_EXT | LLL_CLIENT
  //        | LLL_LATENCY | LLL_USER | LLL_COUNT*/,
  //        xmpp_lwsl_emit_weechat);

  //if (!xmpp_config_init())
  //    return WEECHAT_RC_ERROR;

  //xmpp_config_read();

  //xmpp_command_init();

  //xmpp_api_init();

  //xmpp_completion_init();

  //xmpp_hook_timer = weechat_hook_timer(0.1 * 1000, 0, 0,
  //                                      &xmpp_workspace_timer_cb,
  //                                      NULL, NULL);

    if (!weechat_bar_search("typing"))
    {
        weechat_bar_new("typing", "off", "400", "window", "${typing}",
                        "bottom", "horizontal", "vertical",
                        "1", "1", "default", "default", "default", "default",
                        "off", "xmpp_typing");
    }

  //xmpp_typing_bar_item = weechat_bar_item_new("xmpp_typing",
  //                                             &xmpp_buffer_typing_bar_cb,
  //                                             NULL, NULL);

    return WEECHAT_RC_OK;
}

int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
    /* make C compiler happy */
    (void) plugin;

    if (xmpp_typing_bar_item)
        weechat_bar_item_remove(xmpp_typing_bar_item);

    if (xmpp_hook_timer)
        weechat_unhook(xmpp_hook_timer);

  //xmpp_config_write();

  //xmpp_workspace_disconnect_all();

  //xmpp_workspace_free_all();

    return WEECHAT_RC_OK;
}
