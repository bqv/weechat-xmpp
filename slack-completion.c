// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-emoji.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-completion.h"

void slack_completion_init()
{
    weechat_hook_command_run("/input return",
                             &slack_emoji_input_replace_cb,
                             NULL, NULL);
    
    weechat_hook_command_run("/input complete*",
                             &slack_emoji_input_complete_cb,
                             NULL, NULL);
    
    weechat_hook_completion("slack_emoji",
                            N_("slack emoji"),
                            &slack_emoji_complete_by_name_cb,
                            NULL, NULL);
}
