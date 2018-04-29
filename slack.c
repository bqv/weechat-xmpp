#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-config.h"
#include "slack-command.h"


WEECHAT_PLUGIN_NAME(SLACK_PLUGIN_NAME);
WEECHAT_PLUGIN_DESCRIPTION(N_("Slack (slack.com) protocol"));
WEECHAT_PLUGIN_AUTHOR("Tony Olagbaiye <frony0@gmail.com>");
WEECHAT_PLUGIN_VERSION(SLACK_PLUGIN_VERSION);
WEECHAT_PLUGIN_LICENSE("MPL2");
WEECHAT_PLUGIN_PRIORITY(6000);

struct t_weechat_plugin *weechat_slack_plugin = NULL;

int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
	(void) argc;
	(void) argv;

    weechat_plugin = plugin;

	if (!slack_config_init())
        return WEECHAT_RC_ERROR;

    slack_config_read();

    slack_command_init();

    return WEECHAT_RC_OK;
}

int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
    /* make C compiler happy */
    (void) plugin;

    return WEECHAT_RC_OK;
}
