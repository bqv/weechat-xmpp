#include <json.h>
#include <string.h>

#include "../weechat-plugin.h"
#include "../slack.h"
#include "../slack-workspace.h"
#include "../slack-api.h"
#include "../slack-channel.h"
#include "../slack-user.h"
#include "../slack-message.h"
#include "slack-api-message.h"
#include "message/slack-api-message-unimplemented.h"
#include "message/slack-api-message-bot-message.h"

static const char *type = "message";

struct stringcase
{
    const char *string;
    int (*func)(struct t_slack_workspace *workspace,
                json_object *message);
};

static struct stringcase cases[] =
{ { "bot_message", &slack_api_message_bot_message }
, { "channel_archive", &slack_api_message_unimplemented }
, { "channel_join", &slack_api_message_unimplemented }
, { "channel_leave", &slack_api_message_unimplemented }
, { "channel_name", &slack_api_message_unimplemented }
, { "channel_purpose", &slack_api_message_unimplemented }
, { "channel_topic", &slack_api_message_unimplemented }
, { "channel_unarchive", &slack_api_message_unimplemented }
, { "file_comment", &slack_api_message_unimplemented }
, { "file_mention", &slack_api_message_unimplemented }
, { "file_share", &slack_api_message_unimplemented }
, { "group_archive", &slack_api_message_unimplemented }
, { "group_join", &slack_api_message_unimplemented }
, { "group_leave", &slack_api_message_unimplemented }
, { "group_name", &slack_api_message_unimplemented }
, { "group_purpose", &slack_api_message_unimplemented }
, { "group_topic", &slack_api_message_unimplemented }
, { "group_unarchive", &slack_api_message_unimplemented }
, { "me_message", &slack_api_message_unimplemented }
, { "message_changed", &slack_api_message_unimplemented }
, { "message_deleted", &slack_api_message_unimplemented }
, { "message_replied", &slack_api_message_unimplemented }
, { "pinned_item", &slack_api_message_unimplemented }
, { "reply_broadcast", &slack_api_message_unimplemented }
, { "thread_broadcast", &slack_api_message_unimplemented }
, { "unpinned_item", &slack_api_message_unimplemented }
};

static int stringcase_cmp(const void *p1, const void *p2)
{
    return strcasecmp(((struct stringcase*)p1)->string, ((struct stringcase*)p2)->string);
}

void slack_api_message_init()
{
    size_t case_count = sizeof(cases) / sizeof(cases[0]);
    qsort(cases, case_count, sizeof(struct stringcase), stringcase_cmp);
}

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

int slack_api_message_message_handle(struct t_slack_workspace *workspace,
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
        return 1; /* silently ignore if user hasn't been loaded yet */

    char *message = slack_message_decode(workspace, text);
    weechat_printf_date_tags(
        ptr_channel->buffer,
        (time_t)atof(ts),
        "slack_message",
        _("%s%s"),
        slack_user_as_prefix(workspace, ptr_user, NULL),
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

int slack_api_message_route_message(struct t_slack_workspace *workspace,
                                    const char *subtype,
                                    json_object *message)
{
    struct stringcase key;
    key.string = type;

    size_t case_count = sizeof(cases) / sizeof(cases[0]);
    void *entry_ptr = bsearch(&key, cases, case_count,
            sizeof(struct stringcase), stringcase_cmp);

    if (entry_ptr)
    {
        struct stringcase *entry = (struct stringcase *)entry_ptr;
        return (*entry->func)(workspace, message);
    }
    else
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: got unhandled message of type: message.%s"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            subtype);
        return 1;
    }
}

int slack_api_message(struct t_slack_workspace *workspace,
                      json_object *message)
{
    json_object *subtype, *channel, *user, *text, *ts;

    subtype = json_object_object_get(message, "subtype");
    if (!subtype)
    { /* normal message */
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

        return slack_api_message_message_handle(workspace,
                json_object_get_string(channel),
                json_object_get_string(user),
                json_object_get_string(text),
                json_object_get_string(ts));
    }
    else
    { /* special message */
        return slack_api_message_route_message(workspace,
                json_object_get_string(subtype),
                message);
    }
}
