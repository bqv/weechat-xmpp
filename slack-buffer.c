// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-buffer.h"

void slack_buffer_get_workspace_and_channel(struct t_gui_buffer *buffer,
                                            struct t_slack_workspace **workspace,
                                            struct t_slack_channel **channel)
{
    struct t_slack_workspace *ptr_workspace;
    struct t_slack_channel *ptr_channel;

    if (!buffer)
        return;

	/* look for a workspace or channel using this buffer */
    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        if (ptr_workspace->buffer == buffer)
        {
            if (workspace)
                *workspace = ptr_workspace;
            return;
        }

        for (ptr_channel = ptr_workspace->channels; ptr_channel;
             ptr_channel = ptr_channel->next_channel)
        {
            if (ptr_channel->buffer == buffer)
            {
                if (workspace)
                    *workspace = ptr_workspace;
                if (channel)
                    *channel = ptr_channel;
                return;
            }
        }
    }

    /* no workspace or channel found */
}

char *slack_buffer_typing_bar_cb(const void *pointer,
                                 void *data,
                                 struct t_gui_bar_item *item,
                                 struct t_gui_window *window,
                                 struct t_gui_buffer *buffer,
                                 struct t_hashtable *extra_info)
{
    struct t_slack_channel_typing *ptr_typing;
    struct t_slack_workspace *workspace;
    struct t_slack_channel *channel;
    char notification[256];
    unsigned typecount;

    (void) pointer;
    (void) data;
    (void) item;
    (void) window;
    (void) extra_info;

    workspace = NULL;
    channel = NULL;

    slack_buffer_get_workspace_and_channel(buffer, &workspace, &channel);

    if (!channel)
        return strdup("");

    typecount = 0;

    for (ptr_typing = channel->typings; ptr_typing;
         ptr_typing = ptr_typing->next_typing)
    {
        switch (++typecount)
        {
            case 1:
                strcpy(notification, ptr_typing->name);
                break;
            case 2:
                strcat(notification, ", ");
                strcat(notification, ptr_typing->name);
                break;
            case 3:
            default:
                strcpy(notification, "Several people");
                break;
        }
    }

    if (typecount)
    {
        strcat(notification, NG_(" is typing...",
                                 " are typing...",
                                 typecount));
        return strdup(notification);
    }
    else
    {
        return strdup("");
    }
}

int slack_buffer_nickcmp_cb(const void *pointer, void *data,
                            struct t_gui_buffer *buffer,
                            const char *nick1,
                            const char *nick2)
{
    struct t_slack_workspace *workspace;

    (void) data;

    if (pointer)
        workspace = (struct t_slack_workspace *)pointer;
    else
        slack_buffer_get_workspace_and_channel(buffer, &workspace, NULL);

    if (workspace)
    {
        return weechat_strcasecmp(nick1, nick2);
    }
    else
    {
        return weechat_strcasecmp(nick1, nick2);
    }
}

int slack_buffer_close_cb(const void *pointer, void *data,
                          struct t_gui_buffer *buffer)
{
    struct t_weechat_plugin *buffer_plugin = NULL;
    struct t_slack_workspace *ptr_workspace = NULL;
    struct t_slack_channel *ptr_channel = NULL;

    buffer_plugin = weechat_buffer_get_pointer(buffer, "plugin");
    if (buffer_plugin == weechat_slack_plugin)
        slack_buffer_get_workspace_and_channel(buffer,
                                               &ptr_workspace, &ptr_channel);

    (void) pointer;
    (void) data;
    (void) buffer;

    if (ptr_workspace)
    {
        if (!ptr_workspace->disconnected)
        {
            //slack_command_quit_workspace(ptr_workspace, NULL);
            slack_workspace_disconnect(ptr_workspace, 0);
        }

        ptr_workspace->buffer = NULL;
    }

    return WEECHAT_RC_OK;
}
