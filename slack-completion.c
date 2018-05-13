// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-emoji.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-completion.h"

void slack_completion_init()
{
    struct t_config_option *option;
    const char *default_template;
    
    /*
    weechat_hook_command_run("/input return",
                             &slack_emoji_input_replace_cb,
                             NULL, NULL);
    
    weechat_hook_command_run("/input complete*",
                             &slack_emoji_input_complete_cb,
                             NULL, NULL);
    */
    weechat_hook_completion("slack_emoji",
                            N_("slack emoji"),
                            &slack_emoji_complete_by_name_cb,
                            NULL, NULL);

    option = weechat_config_get("weechat.completion.default_template");
    default_template = weechat_config_string(option);
    if (!weechat_strcasestr(default_template, "%(slack_emoji)"))
    {
        size_t length = snprintf(NULL, 0, "%s|%s",
                                default_template,
                                "%(slack_emoji)") + 1;
        char *new_template = malloc(length);
        snprintf(new_template, length, "%s|%s",
                 default_template,
                 "%(slack_emoji)");
        weechat_config_option_set(option, new_template, 1);
        free(new_template);
    }
}
