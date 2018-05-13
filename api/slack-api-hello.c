// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <json.h>

#include "../weechat-plugin.h"
#include "../slack.h"
#include "../slack-workspace.h"
#include "../slack-api.h"
#include "slack-api-hello.h"
#include "../request/slack-request-channels-list.h"
#include "../request/slack-request-users-list.h"
#include "../request/slack-request-emoji-list.h"

int slack_api_hello_handle(struct t_slack_workspace *workspace)
{
    struct t_slack_request *request;

    weechat_printf(
        workspace->buffer,
        _("%s%s: connected!"),
        weechat_prefix("network"), SLACK_PLUGIN_NAME);

    request = slack_request_users_list(workspace,
            weechat_config_string(
                workspace->options[SLACK_WORKSPACE_OPTION_TOKEN]),
            "");
    if (request)
        slack_workspace_register_request(workspace, request);

    request = slack_request_channels_list(workspace,
            weechat_config_string(
                workspace->options[SLACK_WORKSPACE_OPTION_TOKEN]),
            "");
    if (request)
        slack_workspace_register_request(workspace, request);

    request = slack_request_emoji_list(workspace,
            weechat_config_string(
                workspace->options[SLACK_WORKSPACE_OPTION_TOKEN]));
    if (request)
        slack_workspace_register_request(workspace, request);

    return 1;
}

int slack_api_hello(struct t_slack_workspace *workspace,
                    json_object *message)
{
    (void) message;

    return slack_api_hello_handle(workspace);
}
