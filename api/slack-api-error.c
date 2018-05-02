#include <json.h>

#include "../weechat-plugin.h"
#include "../slack.h"
#include "../slack-workspace.h"
#include "../slack-api.h"
#include "slack-api-error.h"

static const char *type = "error";

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

int slack_api_error_handle(struct t_slack_workspace *workspace,
                           int code, const char *msg)
{
    weechat_printf(
        workspace->buffer,
        _("%s%s: error %d: %s"),
        weechat_prefix("error"), SLACK_PLUGIN_NAME,
        code, msg);

    return 0;
}

int slack_api_error(struct t_slack_workspace *workspace,
                    json_object *message)
{
    json_object *error, *code, *msg;

    error = json_object_object_get(message, "error");
    if (!json_valid(error, workspace))
        return 0;
    
    code = json_object_object_get(error, "code");
    if (!json_valid(code, workspace))
        return 0;
    
    msg = json_object_object_get(error, "msg");
    if (!json_valid(msg, workspace))
        return 0;

    return slack_api_error_handle(workspace,
            json_object_get_int(code),
            json_object_get_string(msg));
}
