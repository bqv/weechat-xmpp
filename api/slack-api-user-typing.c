#include <json.h>

#include "../weechat-plugin.h"
#include "../slack.h"
#include "../slack-workspace.h"
#include "../slack-user.h"
#include "../slack-channel.h"
#include "../slack-api.h"
#include "slack-api-user-typing.h"

static const char *type = "user_typing";

static inline int json_valid(json_object *object, struct t_slack_workspace *workspace)
{
    if (!object)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error handling websocket %s%s%s message: "
              "unexpected response from server"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            weechat_color("chat_value"), type, weechat_color("reset"));
        return 0;
    }

    return 1;
}

int slack_api_user_typing_handle(struct t_slack_workspace *workspace,
                                 const char *channel, const char *user)
{
    struct t_slack_channel *ptr_channel;
    struct t_slack_user *ptr_user;

    ptr_channel = slack_channel_search(workspace, channel);
    if (!ptr_channel)
        return 1; /* silently ignore if channel hasn't been loaded yet */
    ptr_user = slack_user_search(workspace, user);
    if (!ptr_user)
        return 1; /* silently ignore if user hasn't been loaded yet */

    slack_channel_add_typing(ptr_channel, ptr_user);

    return 1;
}

int slack_api_user_typing(struct t_slack_workspace *workspace,
                          json_object *message)
{
    json_object *channel, *user;

    channel = json_object_object_get(message, "channel");
    if (!json_valid(channel, workspace))
        return 0;
    
    user = json_object_object_get(message, "user");
    if (!json_valid(user, workspace))
        return 0;

    return slack_api_user_typing_handle(workspace,
            json_object_get_string(channel),
            json_object_get_string(user));
}
