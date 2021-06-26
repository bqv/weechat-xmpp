// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-config.h"
#include "slack-emoji.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-user.h"
#include "slack-buffer.h"
#include "slack-completion.h"

void slack_completion_channel_nicks_add_speakers(struct t_gui_completion *completion,
                                                 struct t_slack_workspace *workspace,
                                                 struct t_slack_channel *channel,
                                                 int highlight)
{
    struct t_slack_user *user;
    const char *member;
    int list_size, i;

    if (channel->members_speaking[highlight])
    {
        list_size = weechat_list_size(channel->members_speaking[highlight]);
        for (i = 0; i < list_size; i++)
        {
            member = weechat_list_string (
                weechat_list_get(channel->members_speaking[highlight], i));
            if (member)
            {
                user = slack_user_search(workspace, member);
                if (user)
                    weechat_hook_completion_list_add(completion,
                                                     user->profile.display_name,
                                                     1, WEECHAT_LIST_POS_BEGINNING);
            }
        }
    }
}

int slack_completion_channel_nicks_cb(const void *pointer, void *data,
                                      const char *completion_item,
                                      struct t_gui_buffer *buffer,
                                      struct t_gui_completion *completion)
{
    struct t_slack_workspace *ptr_workspace;
    struct t_slack_channel *ptr_channel;
    struct t_slack_channel_member *ptr_member;
    struct t_slack_user *ptr_user;

    
    (void) pointer;
    (void) data;
    (void) completion_item;
    
    ptr_workspace = NULL;
    ptr_channel = NULL;
    slack_buffer_get_workspace_and_channel(buffer, &ptr_workspace, &ptr_channel);

    if (ptr_channel)
    {
        switch (ptr_channel->type)
        {
        case SLACK_CHANNEL_TYPE_CHANNEL:
        case SLACK_CHANNEL_TYPE_GROUP:
        case SLACK_CHANNEL_TYPE_MPIM:
        case SLACK_CHANNEL_TYPE_IM:
            for (ptr_member = ptr_channel->members; ptr_member;
                    ptr_member = ptr_member->next_member)
            {
                ptr_user = slack_user_search(ptr_workspace, ptr_member->id);
                if (ptr_user)
                    weechat_hook_completion_list_add(completion,
                                                     ptr_user->profile.display_name,
                                                     1, WEECHAT_LIST_POS_SORT);
            }
            /* add recent speakers on channel */
            if (weechat_config_integer(slack_config_look_nick_completion_smart) == SLACK_CONFIG_NICK_COMPLETION_SMART_SPEAKERS)
            {
                slack_completion_channel_nicks_add_speakers(completion, ptr_workspace, ptr_channel, 0);
            }
            /* add members whose make highlights on me recently on this channel */
            if (weechat_config_integer(slack_config_look_nick_completion_smart) == SLACK_CONFIG_NICK_COMPLETION_SMART_SPEAKERS_HIGHLIGHTS)
            {
                slack_completion_channel_nicks_add_speakers(completion, ptr_workspace, ptr_channel, 1);
            }
            /* add self member at the end */
            weechat_hook_completion_list_add(completion,
                                             ptr_workspace->nick,
                                             1, WEECHAT_LIST_POS_END);
            break;
        }
    }

    return WEECHAT_RC_OK;
}

int slack_completion_workspaces_cb(const void *pointer, void *data,
                                   const char *completion_item,
                                   struct t_gui_buffer *buffer,
                                   struct t_gui_completion *completion)
{
    struct t_slack_workspace *ptr_workspace;

    
    (void) pointer;
    (void) data;
    (void) completion_item;
    (void) buffer;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        weechat_hook_completion_list_add(completion, ptr_workspace->domain,
                                         0, WEECHAT_LIST_POS_SORT);
    }

    return WEECHAT_RC_OK;
}

void slack_completion_init()
{
    struct t_config_option *option;
    const char *default_template;

    
    weechat_hook_completion ("nick",
                             N_("nicks of current Slack channel"),
                             &slack_completion_channel_nicks_cb,
                             NULL, NULL);
    
    weechat_hook_completion("slack_workspace",
                            N_("slack workspaces"),
                            &slack_completion_workspaces_cb,
                            NULL, NULL);

    weechat_hook_completion("slack_emoji",
                            N_("slack emoji"),
                            &slack_emoji_complete_by_name_cb,
                            NULL, NULL);

    option = weechat_config_get("weechat.completion.default_template");
    default_template = weechat_config_string(option);
    if (!weechat_strcasestr(default_template, "%(slack_emoji)"))
    {
        size_t length = snprintf(NULL, 0, "%s|%s",
                                default_template,
                                "%(slack_emoji)") + 1;
        char *new_template = malloc(length);
        snprintf(new_template, length, "%s|%s",
                 default_template,
                 "%(slack_emoji)");
        weechat_config_option_set(option, new_template, 1);
        free(new_template);
    }
}
