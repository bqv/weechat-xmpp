#include <json.h>
#include <string.h>

#include "../../weechat-plugin.h"
#include "../../slack.h"
#include "../../slack-workspace.h"
#include "../../slack-message.h"
#include "../../slack-api.h"
#include "../../slack-channel.h"
#include "../../slack-user.h"
#include "../slack-api-message.h"
#include "slack-api-message-slackbot-response.h"

static const char *subtype = "slackbot_response";

static inline int json_valid(json_object *object, struct t_slack_workspace *workspace)
{
    if (!object)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error handling websocket %smessage.%s%s message: "
              "unexpected response from server"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            weechat_color("chat_value"), subtype, weechat_color("reset"));
        return 0;
    }

    return 1;
}

int slack_api_message_slackbot_response_handle(struct t_slack_workspace *workspace,
                                               const char *channel, const char *user,
                                               const char *text, const char *ts)
{
    struct t_slack_channel *ptr_channel;
    struct t_slack_user *ptr_user;
    struct t_slack_channel_typing *ptr_typing;

    ptr_channel = slack_channel_search(workspace, channel);
    if (!ptr_channel)
        return 1; /* silently ignore if channel hasn't been loaded yet */
    ptr_user = slack_user_search(workspace, user);
    if (!ptr_user)
        return 1; /* silently ignore if bot user hasn't been loaded yet */

    char *message = slack_message_decode(workspace, text);
    weechat_printf_date_tags(
        ptr_channel->buffer,
        (time_t)atof(ts),
        "slack_message,slack_slackbot_response",
        _("%s%s"),
        slack_user_as_prefix(workspace, ptr_user, "slackbot"),
        message);
    free(message);

    ptr_typing = slack_channel_typing_search(ptr_channel,
                                             ptr_user->profile.display_name);
    if (ptr_typing)
    {
        slack_channel_typing_free(ptr_channel, ptr_typing);
        slack_channel_typing_cb(ptr_channel, NULL, 0);
    }

    return 1;
}

int slack_api_message_slackbot_response(struct t_slack_workspace *workspace,
                                  json_object *message)
{
    json_object *channel, *user, *text, *ts;
    channel = json_object_object_get(message, "channel");
    if (!json_valid(channel, workspace))
        return 0;

    user = json_object_object_get(message, "user");
    if (!json_valid(user, workspace))
        return 0;

    text = json_object_object_get(message, "text");
    if (!json_valid(text, workspace))
        return 0;

    ts = json_object_object_get(message, "ts");
    if (!json_valid(ts, workspace))
        return 0;

    return slack_api_message_slackbot_response_handle(workspace,
            json_object_get_string(channel),
            json_object_get_string(user),
            json_object_get_string(text),
            json_object_get_string(ts));
}

