// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "config.hh"
#include "account.hh"
#include "channel.hh"
#include "user.hh"
#include "buffer.hh"
#include "completion.hh"

void completion__channel_nicks_add_speakers(struct t_gui_completion *completion,
                                            weechat::account *account,
                                            weechat::channel *channel,
                                            int highlight)
{
    weechat::user *user;
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
                user = weechat::user::search(account, member);
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
    weechat::account *ptr_account;
    weechat::channel *ptr_channel;
    weechat::user *ptr_user;

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
        case weechat::channel::chat_type::MUC:
        case weechat::channel::chat_type::PM:
            for (auto& ptr_member : ptr_channel->members)
            {
                ptr_user = weechat::user::search(ptr_account, ptr_member.second.id);
                if (ptr_user)
                    weechat_hook_completion_list_add(completion,
                                                     ptr_user->profile.display_name,
                                                     1, WEECHAT_LIST_POS_SORT);
            }
            /* add recent speakers on channel */
            if (weechat_config_integer(weechat::config::instance->look.nick_completion_smart) == static_cast<int>(weechat::config::nick_completion::SMART_SPEAKERS))
            {
                completion__channel_nicks_add_speakers(completion, ptr_account, ptr_channel, 0);
            }
            /* add members whose make highlights on me recently on this channel */
            if (weechat_config_integer(weechat::config::instance->look.nick_completion_smart) == static_cast<int>(weechat::config::nick_completion::SMART_SPEAKERS_HIGHLIGHTS))
            {
                completion__channel_nicks_add_speakers(completion, ptr_account, ptr_channel, 1);
            }
            /* add self member at the end */
            weechat_hook_completion_list_add(completion,
                                             ptr_account->name.data(),
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
    /* make C compiler happy */
    (void) pointer;
    (void) data;
    (void) completion_item;
    (void) buffer;

    for (auto& ptr_account : weechat::accounts)
    {
        weechat_hook_completion_list_add(completion, ptr_account.second.jid().data(),
                                         0, WEECHAT_LIST_POS_SORT);
    }

    return WEECHAT_RC_OK;
}

void completion__init()
{
    struct t_config_option *option;
    const char *default_template;


    weechat_hook_completion("nick",
                            N_("nicks of current buffer"),
                            &completion__channel_nicks_cb,
                            NULL, NULL);

    weechat_hook_completion("xmpp_account",
                            N_("xmpp accounts"),
                            &completion__accounts_cb,
                            NULL, NULL);

    option = weechat_config_get("weechat.completion.default_template");
    default_template = weechat_config_string(option);
    if (!weechat_strcasestr(default_template, "%(xmpp_account)"))
    {
        size_t length = snprintf(NULL, 0, "%s|%s",
                                default_template,
                                "%(xmpp_account)") + 1;
        char *new_template = new char[length];
        snprintf(new_template, length, "%s|%s",
                 default_template,
                 "%(xmpp_account)");
        weechat_config_option_set(option, new_template, 1);
        delete[] new_template;
    }
}
