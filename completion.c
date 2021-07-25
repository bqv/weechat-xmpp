// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "config.h"
#include "account.h"
#include "channel.h"
#include "user.h"
#include "buffer.h"
#include "completion.h"

void completion__channel_nicks_add_speakers(struct t_gui_completion *completion,
                                            struct t_account *account,
                                            struct t_channel *channel,
                                            int highlight)
{
    struct t_user *user;
    const char *member;
    int list_size, i;

    if (channel->members_speaking[highlight])
    {
        list_size = weechat_list_size(channel->members_speaking[highlight]);
        for (i = 0; i < list_size; i++)
        {
            member = weechat_list_string(
                weechat_list_get(channel->members_speaking[highlight], i));
            if (member)
            {
                user = user__search(account, member);
                if (user)
                    weechat_hook_completion_list_add(completion,
                                                     user->profile.display_name,
                                                     1, WEECHAT_LIST_POS_BEGINNING);
            }
        }
    }
}

int completion__channel_nicks_cb(const void *pointer, void *data,
                                 const char *completion_item,
                                 struct t_gui_buffer *buffer,
                                 struct t_gui_completion *completion)
{
    struct t_account *ptr_account;
    struct t_channel *ptr_channel;
    struct t_channel_member *ptr_member;
    struct t_user *ptr_user;

    /* make C compiler happy */
    (void) pointer;
    (void) data;
    (void) completion_item;
    
    ptr_account = NULL;
    ptr_channel = NULL;
    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (ptr_channel)
    {
        switch (ptr_channel->type)
        {
        case CHANNEL_TYPE_MUC:
        case CHANNEL_TYPE_PM:
            for (ptr_member = ptr_channel->members; ptr_member;
                 ptr_member = ptr_member->next_member)
            {
                ptr_user = user__search(ptr_account, ptr_member->id);
                if (ptr_user)
                    weechat_hook_completion_list_add(completion,
                                                     ptr_user->profile.display_name,
                                                     1, WEECHAT_LIST_POS_SORT);
            }
            /* add recent speakers on channel */
            if (weechat_config_integer(config_look_nick_completion_smart) == CONFIG_NICK_COMPLETION_SMART_SPEAKERS)
            {
                completion__channel_nicks_add_speakers(completion, ptr_account, ptr_channel, 0);
            }
            /* add members whose make highlights on me recently on this channel */
            if (weechat_config_integer(config_look_nick_completion_smart) == CONFIG_NICK_COMPLETION_SMART_SPEAKERS_HIGHLIGHTS)
            {
                completion__channel_nicks_add_speakers(completion, ptr_account, ptr_channel, 1);
            }
            /* add self member at the end */
            weechat_hook_completion_list_add(completion,
                                             ptr_account->name,
                                             1, WEECHAT_LIST_POS_END);
            break;
        }
    }

    return WEECHAT_RC_OK;
}

int completion__accounts_cb(const void *pointer, void *data,
                            const char *completion_item,
                            struct t_gui_buffer *buffer,
                            struct t_gui_completion *completion)
{
    struct t_account *ptr_account;

    /* make C compiler happy */
    (void) pointer;
    (void) data;
    (void) completion_item;
    (void) buffer;

    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account->next_account)
    {
        weechat_hook_completion_list_add(completion, account_jid(ptr_account),
                                         0, WEECHAT_LIST_POS_SORT);
    }

    return WEECHAT_RC_OK;
}

void completion__init()
{
    struct t_config_option *option;
    const char *default_template;

    
    weechat_hook_completion("nick",
                            N_("nicks of current Slack channel"),
                            &completion__channel_nicks_cb,
                            NULL, NULL);
    
    weechat_hook_completion("account",
                            N_("xmpp accounts"),
                            &completion__accounts_cb,
                            NULL, NULL);

    option = weechat_config_get("weechat.completion.default_template");
    default_template = weechat_config_string(option);
    if (!weechat_strcasestr(default_template, "%(account)"))
    {
        size_t length = snprintf(NULL, 0, "%s|%s",
                                default_template,
                                "%(account)") + 1;
        char *new_template = malloc(length);
        snprintf(new_template, length, "%s|%s",
                 default_template,
                 "%(account)");
        weechat_config_option_set(option, new_template, 1);
        free(new_template);
    }
}
