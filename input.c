// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
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
    struct xmpp_stanza_t *message;

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

        message = xmpp_message_new(account->context, "chat", channel->id, NULL);
        xmpp_message_set_body(message, text);
        xmpp_send(account->connection, message);
        xmpp_stanza_release(message);
        weechat_printf(channel->buffer, "-> %s: %s",
                       weechat_config_string(account->options[ACCOUNT_OPTION_JID]),
                       text);
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
