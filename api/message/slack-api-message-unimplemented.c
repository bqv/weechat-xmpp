#include <json.h>
#include <string.h>

#include "../../weechat-plugin.h"
#include "../../slack.h"
#include "../../slack-workspace.h"
#include "../../slack-api.h"
#include "../../slack-channel.h"
#include "../../slack-user.h"
#include "../slack-api-message.h"
#include "slack-api-message-unimplemented.h"

static const char *subtype = "unimplemented";

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

int slack_api_message_unimplemented(struct t_slack_workspace *workspace,
                                    json_object *message)
{
    json_object *subtype = json_object_object_get(message, "subtype");
    if (!json_valid(subtype, workspace))
        return 0;

    weechat_printf(
        workspace->buffer,
        _("%s%s: got unhandled message of type: message.%s"),
        weechat_prefix("error"), SLACK_PLUGIN_NAME,
        json_object_get_string(subtype));

    return 1;
}

