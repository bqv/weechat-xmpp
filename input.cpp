// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <stdint.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "account.hh"
#include "channel.hh"
#include "buffer.hh"
#include "message.hh"
#include "input.hh"

int input__data(struct t_gui_buffer *buffer, const char *text)
{
    weechat::account *account = NULL;
    weechat::channel *channel = NULL;

    buffer__get_account_and_channel(buffer, &account, &channel);

    if (!account)
        return WEECHAT_RC_ERROR;

    if (channel)
    {
        if (!account->connected())
        {
            weechat_printf(buffer,
                           _("%s%s: you are not connected to server"),
                           weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
            return WEECHAT_RC_OK;
        }

        if (channel->send_message(channel->id, text) == WEECHAT_RC_OK)
            return WEECHAT_RC_OK;
        else
        {
            return WEECHAT_RC_OK_EAT;
        }
    }
    else
    {
        weechat_printf(buffer,
                       _("%s%s: this buffer is not a channel!"),
                       weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }
}

int input__data_cb(const void *pointer, void *data,
                   struct t_gui_buffer *buffer,
                   const char *text)
{
    (void) pointer;
    (void) data;

    return input__data(buffer, text);
}

int input__typing(struct t_gui_buffer *buffer)
{
    weechat::account *account = NULL;
    weechat::channel *channel = NULL;

    buffer__get_account_and_channel(buffer, &account, &channel);

    if (account && account->connected() && channel)
    {
        channel->send_reads();
        channel->send_typing(weechat::user::search(account, account->jid_device().data()));
    }

    return WEECHAT_RC_OK;
}

int input__text_changed_cb(const void *pointer, void *data,
                           const char *signal, const char *type_data,
                           void *signal_data)
{
    (void) pointer;
    (void) data;
    (void) signal;
    (void) type_data;

    return input__typing((struct t_gui_buffer*)signal_data);
}
