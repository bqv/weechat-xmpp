// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <string.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "account.h"
#include "channel.h"
#include "buffer.h"

void buffer__get_account_and_channel(struct t_gui_buffer *buffer,
                                     struct t_account **account,
                                     struct t_channel **channel)
{
    struct t_account *ptr_account;
    struct t_channel *ptr_channel;

    if (!buffer)
        return;

    /* look for a account or channel using this buffer */
    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account->next_account)
    {
        if (ptr_account->buffer == buffer)
        {
            if (account)
                *account = ptr_account;
            return;
        }

        for (ptr_channel = ptr_account->channels; ptr_channel;
             ptr_channel = ptr_channel->next_channel)
        {
            if (ptr_channel->buffer == buffer)
            {
                if (account)
                    *account = ptr_account;
                if (channel)
                    *channel = ptr_channel;
                return;
            }
        }
    }

    /* no account or channel found */
}

char *buffer__typing_bar_cb(const void *pointer, void *data,
                            struct t_gui_bar_item *item,
                            struct t_gui_window *window,
                            struct t_gui_buffer *buffer,
                            struct t_hashtable *extra_info)
{
    struct t_channel_typing *ptr_typing;
    struct t_account *account;
    struct t_channel *channel;
    char notification[256];
    unsigned typecount;

    (void) pointer;
    (void) data;
    (void) item;
    (void) window;
    (void) extra_info;

    account = NULL;
    channel = NULL;

    buffer__get_account_and_channel(buffer, &account, &channel);

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

int buffer__nickcmp_cb(const void *pointer, void *data,
                       struct t_gui_buffer *buffer,
                       const char *nick1,
                       const char *nick2)
{
    struct t_account *account;

    (void) data;

    if (pointer)
        account = (struct t_account *)pointer;
    else
        buffer__get_account_and_channel(buffer, &account, NULL);

    if (account)
    {
        return weechat_strcasecmp(nick1, nick2);
    }
    else
    {
        return weechat_strcasecmp(nick1, nick2);
    }
}

int buffer__close_cb(const void *pointer, void *data,
                     struct t_gui_buffer *buffer)
{
    struct t_weechat_plugin *buffer_plugin = NULL;
    struct t_account *ptr_account = NULL;
    struct t_channel *ptr_channel = NULL;

    buffer_plugin = weechat_buffer_get_pointer(buffer, "plugin");
    if (buffer_plugin == weechat_plugin)
        buffer__get_account_and_channel(buffer,
                                               &ptr_account, &ptr_channel);

    (void) pointer;
    (void) data;
    (void) buffer;

    if (ptr_account)
    {
        if (!ptr_account->disconnected)
        {
            //command_quit_account(ptr_account, NULL);
            account__disconnect(ptr_account, 0);
        }

        ptr_account->buffer = NULL;
    }

    return WEECHAT_RC_OK;
}
