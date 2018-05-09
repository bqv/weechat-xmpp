// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <libwebsockets.h>
#include <stdlib.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-buffer.h"
#include "slack-request.h"
#include "slack-message.h"
#include "slack-input.h"
#include "request/slack-request-chat-postmessage.h"

int slack_input_data(struct t_gui_buffer *buffer, const char *input_data)
{
    struct t_slack_workspace *workspace = NULL;
    struct t_slack_channel *channel = NULL;
    struct t_slack_request *request;
    char *text;

    slack_buffer_get_workspace_and_channel(buffer, &workspace, &channel);

    if (!workspace)
        return WEECHAT_RC_ERROR;

    if (channel)
    {
        if (!workspace->is_connected)
        {
            weechat_printf(buffer,
                           _("%s%s: you are not connected to server"),
                           weechat_prefix("error"), SLACK_PLUGIN_NAME);
            return WEECHAT_RC_OK;
        }

        text = malloc(SLACK_MESSAGE_MAX_LENGTH);
        if (!text)
        {
            weechat_printf(buffer,
                           _("%s%s: error allocating string"),
                           weechat_prefix("error"), SLACK_PLUGIN_NAME);
            return WEECHAT_RC_ERROR;
        }
        lws_urlencode(text, input_data, SLACK_MESSAGE_MAX_LENGTH);

        request = slack_request_chat_postmessage(workspace,
                    weechat_config_string(
                        workspace->options[SLACK_WORKSPACE_OPTION_TOKEN]),
                    channel->id, text);
        if (request)
            slack_workspace_register_request(workspace, request);

        free(text);
    }
    else
    {
        weechat_printf(buffer,
                       _("%s%s: this buffer is not a channel!"),
                       weechat_prefix("error"), SLACK_PLUGIN_NAME);
    }

    return WEECHAT_RC_OK;
}

int slack_input_data_cb(const void *pointer, void *data,
                        struct t_gui_buffer *buffer,
                        const char *input_data)
{
    (void) pointer;
    (void) data;

    return slack_input_data(buffer, input_data);
}
