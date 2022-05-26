// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdint.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "account.hh"
#include "channel.hh"
#include "buffer.hh"

void buffer__get_account_and_channel(struct t_gui_buffer *buffer,
                                     weechat::account **account,
                                     weechat::channel **channel)
{
    if (!buffer)
        return;

    *account = nullptr;
    *channel = nullptr;

    /* look for a account or channel using this buffer */
    for (auto& ptr_account : weechat::accounts)
    {
        if (ptr_account.second.buffer == buffer)
        {
            if (account)
                *account = &ptr_account.second;
            return;
        }

        for (auto& ptr_channel : ptr_account.second.channels)
        {
            if (ptr_channel.second.buffer == buffer)
            {
                if (account)
                    *account = &ptr_account.second;
                if (channel)
                    *channel = &ptr_channel.second;
                return;
            }
        }
    }
}

char *buffer__typing_bar_cb(const void *pointer, void *data,
                            struct t_gui_bar_item *item,
                            struct t_gui_window *window,
                            struct t_gui_buffer *buffer,
                            struct t_hashtable *extra_info)
{
    weechat::account *account;
    weechat::channel *channel;
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
        return strndup("", 0);

    typecount = 0;

    for (auto& ptr_typing : channel->typings)
    {
        switch (++typecount)
        {
            case 1:
                strcpy(notification, ptr_typing.name);
                break;
            case 2:
                strcat(notification, ", ");
                strcat(notification, ptr_typing.name);
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
        return strndup("", 0);
    }
}

int buffer__nickcmp_cb(const void *pointer, void *data,
                       struct t_gui_buffer *buffer,
                       const char *nick1,
                       const char *nick2)
{
    weechat::account *account;

    (void) data;

    if (pointer)
        account = (weechat::account *)pointer;
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
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;

    (void) pointer;
    (void) data;

    buffer_plugin = (struct t_weechat_plugin*)weechat_buffer_get_pointer(buffer, "plugin");
    if (buffer_plugin != weechat_plugin)
        return WEECHAT_RC_OK;
    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    const char* type = weechat_buffer_get_string(buffer, "localvar_type");

    if (weechat_strcasecmp(type, "server") == 0)
    {
        if (ptr_account)
        {
            if (ptr_account->connected())
            {
                ptr_account->disconnect(0);
            }

            ptr_account->buffer = NULL;
        }
    }
    else if (weechat_strcasecmp(type, "channel") == 0)
    {
        if (ptr_account && ptr_channel)
        {
            if (ptr_account->connected())
            {
                ptr_account->channels.erase(ptr_channel->name);
            }
        }
    }
    else if (weechat_strcasecmp(type, "private") == 0)
    {
        if (ptr_account && ptr_channel)
        {
            if (ptr_account->connected())
            {
                ptr_account->channels.erase(ptr_channel->name);
            }
        }
    }
    else
    {
    }

    return WEECHAT_RC_OK;
}
