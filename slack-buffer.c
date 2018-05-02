#include "weechat-plugin.h"
#include "slack.h"
#include "slack-buffer.h"
#include "slack-workspace.h"
#include "slack-channel.h"

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
            slack_workspace_disconnect(ptr_workspace, 0, 0);
        }

        ptr_workspace->buffer = NULL;
    }

    return WEECHAT_RC_OK;
}
