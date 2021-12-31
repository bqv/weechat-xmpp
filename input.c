// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <stdint.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "account.h"
#include "channel.h"
#include "buffer.h"
#include "message.h"
#include "input.h"

int input__data(struct t_gui_buffer *buffer, const char *text)
{
    struct t_account *account = NULL;
    struct t_channel *channel = NULL;

    buffer__get_account_and_channel(buffer, &account, &channel);

    if (!account)
        return WEECHAT_RC_ERROR;

    if (channel)
    {
        if (!account->is_connected)
        {
            weechat_printf(buffer,
                           _("%s%s: you are not connected to server"),
                           weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
            return WEECHAT_RC_OK;
        }

        channel__send_message(account, channel, channel->id, text);
    }
    else
    {
        weechat_printf(buffer,
                       _("%s%s: this buffer is not a channel!"),
                       weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
    }

    return WEECHAT_RC_OK;
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
    struct t_account *account = NULL;
    struct t_channel *channel = NULL;

    buffer__get_account_and_channel(buffer, &account, &channel);

    if (account && account->is_connected && channel)
    {
        channel__send_reads(account, channel);
        channel__send_typing(account, channel, NULL);
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

    return input__typing(signal_data);
}
