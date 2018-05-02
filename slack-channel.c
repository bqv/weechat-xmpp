#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-input.h"
#include "slack-buffer.h"

struct t_slack_channel *slack_channel_search(struct t_slack_workspace *workspace,
                                             const char *id)
{
    struct t_slack_channel *ptr_channel;

    if (!workspace || !id)
        return NULL;

    for (ptr_channel = workspace->channels; ptr_channel;
         ptr_channel = ptr_channel->next_channel)
    {
        if (weechat_strcasecmp(ptr_channel->id, id) == 0)
            return ptr_channel;
    }

    return NULL;
}

struct t_gui_buffer *slack_channel_search_buffer(struct t_slack_workspace *workspace,
                                                 enum t_slack_channel_type type,
                                                 const char *name)
{
    struct t_hdata *hdata_buffer;
    struct t_gui_buffer *ptr_buffer;
    const char *ptr_type, *ptr_workspace_name, *ptr_channel_name;

    hdata_buffer = weechat_hdata_get("buffer");
    ptr_buffer = weechat_hdata_get_list(hdata_buffer, "gui_buffers");

    while (ptr_buffer)
    {
        if (weechat_buffer_get_pointer(ptr_buffer, "plugin") == weechat_slack_plugin)
        {
            ptr_type = weechat_buffer_get_string(ptr_buffer, "localvar_type");
            ptr_workspace_name = weechat_buffer_get_string(ptr_buffer,
                                                           "localvar_server");
            ptr_channel_name = weechat_buffer_get_string(ptr_buffer,
                                                         "localvar_channel");
            if (ptr_type && ptr_type[0]
                && ptr_workspace_name && ptr_workspace_name[0]
                && ptr_channel_name && ptr_channel_name[0]
                && (   ((   (type == SLACK_CHANNEL_TYPE_CHANNEL)
                         || (type == SLACK_CHANNEL_TYPE_GROUP))
                        && (strcmp(ptr_type, "channel") == 0))
                    || ((   (type == SLACK_CHANNEL_TYPE_MPIM)
                         || (type == SLACK_CHANNEL_TYPE_IM))
                        && (strcmp(ptr_type, "private") == 0)))
                && (strcmp(ptr_workspace_name, workspace->domain) == 0)
                && (weechat_strcasecmp(ptr_channel_name, name) == 0))
            {
                return ptr_buffer;
            }
        }
        ptr_buffer = weechat_hdata_move(hdata_buffer, ptr_buffer, 1);
    }

    return NULL;
}

struct t_gui_buffer *slack_channel_create_buffer(struct t_slack_workspace *workspace,
                                                 enum t_slack_channel_type type,
                                                 const char *name)
{
    struct t_gui_buffer *ptr_buffer;
    int buffer_created, current_buffer_number;
    const char *short_name, *localvar_channel;
    char buffer_name[256];

    buffer_created = 0;

    snprintf(buffer_name, sizeof(buffer_name),
             "%s.%s", workspace->domain, name);

    ptr_buffer = slack_channel_search_buffer(workspace, type, name);
    if (ptr_buffer)
    {
        weechat_nicklist_remove_all(ptr_buffer);
    }
    else
    {
        current_buffer_number = weechat_buffer_get_integer(
                weechat_current_buffer(), "number");

        ptr_buffer = weechat_buffer_new(buffer_name,
                                        &slack_input_data_cb, NULL, NULL,
                                        &slack_buffer_close_cb, NULL, NULL);
        if (!ptr_buffer)
            return NULL;

        buffer_created = 1;
    }

    if (buffer_created)
    {
        if (!weechat_buffer_get_integer(ptr_buffer, "short_name_is_set"))
            weechat_buffer_set(ptr_buffer, "short_name", name);
    }
    else
    {
        short_name = weechat_buffer_get_string (ptr_buffer, "short_name");
        localvar_channel = weechat_buffer_get_string (ptr_buffer,
                                                      "localvar_channel");

        if (!short_name ||
                (localvar_channel && (strcmp(localvar_channel, short_name) == 0)))
        {
            weechat_buffer_set (ptr_buffer, "short_name", name);
        }
    }

    weechat_buffer_set(ptr_buffer, "name", buffer_name);
    weechat_buffer_set(ptr_buffer, "localvar_set_type",
                       (type == SLACK_CHANNEL_TYPE_IM ||
                        type == SLACK_CHANNEL_TYPE_MPIM) ? "private" : "channel");
    weechat_buffer_set(ptr_buffer, "localvar_set_nick", workspace->nick);
    weechat_buffer_set(ptr_buffer, "localvar_set_server", workspace->domain);
    weechat_buffer_set(ptr_buffer, "localvar_set_channel", name);

    if (buffer_created)
    {
        (void) weechat_hook_signal_send ("logger_backlog",
                                         WEECHAT_HOOK_SIGNAL_POINTER,
                                         ptr_buffer);
        weechat_buffer_set(ptr_buffer, "input_get_unknown_commands", "1");
        if (type != SLACK_CHANNEL_TYPE_IM)
        {
            weechat_buffer_set(ptr_buffer, "nicklist", "1");
            weechat_buffer_set(ptr_buffer, "nicklist_display_groups", "0");
            weechat_buffer_set_pointer(ptr_buffer, "nicklist_callback",
                                       &slack_buffer_nickcmp_cb);
            weechat_buffer_set_pointer(ptr_buffer, "nicklist_callback_pointer",
                                       workspace);
        }

        weechat_buffer_set(ptr_buffer, "highlight_words_add",
                           workspace->nick);
        weechat_buffer_set(ptr_buffer, "highlight_tags_restrict",
                           "slack_message");
    }

    return ptr_buffer;
}

struct t_slack_channel *slack_channel_new(struct t_slack_workspace *workspace,
                                          enum t_slack_channel_type type,
                                          const char *id, const char *name)
{
    struct t_slack_channel *new_channel, *ptr_channel;
    struct t_gui_buffer *ptr_buffer;

    if (!workspace || !id)
        return NULL;

    ptr_channel = slack_channel_search(workspace, id);
    if (ptr_channel)
    {
        return ptr_channel;
    }

    ptr_buffer = slack_channel_create_buffer(workspace, type, name);
    if (!ptr_buffer)
        return NULL;

    if ((new_channel = malloc(sizeof(*new_channel))) == NULL)
        return NULL;

    new_channel->type = type;
    new_channel->id = strdup(id);
    new_channel->name = strdup(name);
    new_channel->created = 0;

    new_channel->is_general = 0;
    new_channel->name_normalized = NULL;
    new_channel->is_shared = 0;
    new_channel->is_org_shared = 0;
    new_channel->is_member = 0;

    new_channel->topic.value = NULL;
    new_channel->topic.creator = NULL;
    new_channel->topic.last_set = 0;
    new_channel->purpose.value = NULL;
    new_channel->purpose.creator = NULL;
    new_channel->purpose.last_set = 0;
    new_channel->is_archived = 0;

    new_channel->creator = NULL;
    new_channel->last_read = 0.0;
    new_channel->unread_count = 0;
    new_channel->unread_count_display = 0;

    new_channel->is_user_deleted = 0;

    new_channel->members = NULL;
    new_channel->last_member = NULL;
    new_channel->buffer = ptr_buffer;
    new_channel->buffer_as_string = NULL;

    new_channel->prev_channel = NULL;
    new_channel->next_channel = NULL;

    new_channel->prev_channel = workspace->last_channel;
    if (workspace->last_channel)
        (workspace->last_channel)->next_channel = new_channel;
    workspace->last_channel = new_channel;

    return new_channel;
}

void slack_channel_member_free(struct t_slack_channel *channel,
                               struct t_slack_channel_member *member)
{
    struct t_slack_channel_member *new_members;

    if (!channel || !member)
        return;

	/* remove member from members list */
    if (channel->last_member == member)
        channel->last_member = member->prev_member;
    if (member->prev_member)
    {
        (member->prev_member)->next_member = member->next_member;
        new_members = channel->members;
    }
    else
        new_members = member->next_member;

    if (member->next_member)
        (member->next_member)->prev_member = member->prev_member;

    /* free member data */
    if (member->id)
        free(member->id);

    free(member);

    channel->members = new_members;
}

void slack_channel_member_free_all(struct t_slack_channel *channel)
{
    while (channel->members)
        slack_channel_member_free(channel, channel->members);
}

void slack_channel_free(struct t_slack_workspace *workspace,
                        struct t_slack_channel *channel)
{
    struct t_slack_channel *new_channels;

    if (!workspace || !channel)
        return;

	/* remove channel from channels list */
    if (workspace->last_channel == channel)
        workspace->last_channel = channel->prev_channel;
    if (channel->prev_channel)
    {
        (channel->prev_channel)->next_channel = channel->next_channel;
        new_channels = workspace->channels;
    }
    else
        new_channels = channel->next_channel;

    if (channel->next_channel)
        (channel->next_channel)->prev_channel = channel->prev_channel;

    /* free linked lists */
    slack_channel_member_free_all(channel);

    /* free channel data */
    if (channel->id)
        free(channel->id);
    if (channel->name)
        free(channel->name);
    if (channel->name_normalized)
        free(channel->name_normalized);
	if (channel->topic.value)
		free(channel->topic.value);
	if (channel->topic.creator)
		free(channel->topic.creator);
	if (channel->purpose.value)
		free(channel->purpose.value);
	if (channel->purpose.creator)
		free(channel->purpose.creator);
    if (channel->creator)
        free(channel->creator);
    if (channel->buffer_as_string)
        free (channel->buffer_as_string);

    free(channel);

    workspace->channels = new_channels;
}

void slack_channel_free_all(struct t_slack_workspace *workspace)
{
    while (workspace->channels)
        slack_channel_free(workspace, workspace->channels);
}
