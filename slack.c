// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <json.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-config.h"
#include "slack-command.h"
#include "slack-workspace.h"
#include "slack-api.h"
#include "slack-buffer.h"
#include "slack-completion.h"


WEECHAT_PLUGIN_NAME(SLACK_PLUGIN_NAME);
WEECHAT_PLUGIN_DESCRIPTION(N_("Slack (slack.com) protocol"));
WEECHAT_PLUGIN_AUTHOR("Tony Olagbaiye <frony0@gmail.com>");
WEECHAT_PLUGIN_VERSION(SLACK_PLUGIN_VERSION);
WEECHAT_PLUGIN_LICENSE("MPL2");
WEECHAT_PLUGIN_PRIORITY(5500);

struct t_weechat_plugin *weechat_slack_plugin = NULL;

struct t_hook *slack_hook_timer = NULL;

struct t_gui_bar_item *slack_typing_bar_item = NULL;

void slack_lwsl_emit_weechat(int level, const char *line)
{
    char buf[50];
    lwsl_timestamp(level, buf, sizeof(buf));

    weechat_printf(
        NULL,
        _("%s%s: %s%s"),
        weechat_prefix("error"), SLACK_PLUGIN_NAME,
        buf, line);
}

int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
	(void) argc;
	(void) argv;

    weechat_plugin = plugin;

    lws_set_log_level(LLL_ERR | LLL_WARN /*| LLL_NOTICE | LLL_INFO | LLL_DEBUG
            | LLL_PARSER | LLL_HEADER | LLL_EXT | LLL_CLIENT
            | LLL_LATENCY | LLL_USER | LLL_COUNT*/,
            slack_lwsl_emit_weechat);

	if (!slack_config_init())
        return WEECHAT_RC_ERROR;

    slack_config_read();

    slack_command_init();

    slack_api_init();

    slack_completion_init();

    slack_hook_timer = weechat_hook_timer(0.1 * 1000, 0, 0,
                                          &slack_workspace_timer_cb,
                                          NULL, NULL);

    if (!weechat_bar_search("typing"))
    {
        weechat_bar_new("typing", "off", "400", "window", "${typing}",
                        "bottom", "horizontal", "vertical",
                        "1", "1", "default", "default", "default",
                        "off", "slack_typing");
    }

    slack_typing_bar_item = weechat_bar_item_new("slack_typing",
                                                 &slack_buffer_typing_bar_cb,
                                                 NULL, NULL);

    return WEECHAT_RC_OK;
}

int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
    /* make C compiler happy */
    (void) plugin;

    if (slack_typing_bar_item)
        weechat_bar_item_remove(slack_typing_bar_item);

    if (slack_hook_timer)
        weechat_unhook(slack_hook_timer);

    slack_config_write();

    slack_workspace_disconnect_all();

    slack_workspace_free_all();

    return WEECHAT_RC_OK;
}
