// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <utility>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "account.hh"
#include "user.hh"
#include "channel.hh"
#include "buffer.hh"
#include "message.hh"
#include "command.hh"
#include "sexp/driver.hh"

#define MAM_DEFAULT_DAYS 2
#define STR(X) #X

void command__display_account(weechat::account *account)
{
    int num_channels, num_pv;

    if (account->connected())
    {
        num_channels = 0;//xmpp_account_get_channel_count(account);
        num_pv = 0;//xmpp_account_get_pv_count(account);
        weechat_printf(
            NULL,
            " %s %s%s%s %s(%s%s%s) [%s%s%s]%s, %d %s, %d pv",
            (account->connected()) ? "*" : " ",
            weechat_color("chat_server"),
            account->name.data(),
            weechat_color("reset"),
            weechat_color("chat_delimiters"),
            weechat_color("chat_server"),
            account->jid().data(),
            weechat_color("chat_delimiters"),
            weechat_color("reset"),
            (account->connected()) ? _("connected") : _("not connected"),
            weechat_color("chat_delimiters"),
            weechat_color("reset"),
            num_channels,
            NG_("channel", "channels", num_channels),
            num_pv);
    }
    else
    {
        weechat_printf(
            NULL,
            "   %s%s%s %s(%s%s%s)%s",
            weechat_color("chat_server"),
            account->name.data(),
            weechat_color("reset"),
            weechat_color("chat_delimiters"),
            weechat_color("chat_server"),
            account->jid().data(),
            weechat_color("chat_delimiters"),
            weechat_color("reset"));
    }
}

void command__account_list(int argc, char **argv)
{
    int i, one_account_found;
    char *account_name = NULL;

    for (i = 2; i < argc; i++)
    {
        if (!account_name)
            account_name = argv[i];
    }
    if (!account_name)
    {
        if (!weechat::accounts.empty())
        {
            weechat_printf(NULL, "");
            weechat_printf(NULL, _("All accounts:"));
            for (auto& ptr_account2 : weechat::accounts)
            {
                command__display_account(&ptr_account2.second);
            }
        }
        else
            weechat_printf(NULL, _("No account"));
    }
    else
    {
        one_account_found = 0;
        for (auto& ptr_account2 : weechat::accounts)
        {
            if (weechat_strcasestr(ptr_account2.second.name.data(), account_name))
            {
                if (!one_account_found)
                {
                    weechat_printf(NULL, "");
                    weechat_printf(NULL,
                                   _("Servers with \"%s\":"),
                                   account_name);
                }
                one_account_found = 1;
                command__display_account(&ptr_account2.second);
            }
        }
        if (!one_account_found)
            weechat_printf(NULL,
                           _("No account found with \"%s\""),
                           account_name);
    }
}

void command__add_account(const char *name, const char *jid, const char *password)
{
    weechat::account *account = nullptr;
    if (weechat::account::search(account, name, true))
    {
        weechat_printf(
            NULL,
            _("%s%s: account \"%s\" already exists, can't add it!"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            name);
        return;
    }

    if (!jid || !password) {
        weechat_printf(
            NULL,
            _("%s%s: jid and password required"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return;
    }

    ;
    account = &weechat::accounts.emplace(
        std::piecewise_construct, std::forward_as_tuple(name),
        std::forward_as_tuple(weechat::config::instance->file, name)).first->second;
    if (!account)
    {
        weechat_printf(
            NULL,
            _("%s%s: unable to add account"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return;
    }

    account->name = strdup(name);
    if (jid)
        account->jid(jid);
    if (password)
        account->password(password);
    if (jid)
        account->nickname(xmpp_jid_node(account->context, jid));

    weechat_printf(
        NULL,
        _("%s: account %s%s%s %s(%s%s%s)%s added"),
        WEECHAT_XMPP_PLUGIN_NAME,
        weechat_color("chat_server"),
        account->name.data(),
        weechat_color("reset"),
        weechat_color("chat_delimiters"),
        weechat_color("chat_server"),
        jid ? jid : "???",
        weechat_color("chat_delimiters"),
        weechat_color("reset"));
}

void command__account_add(struct t_gui_buffer *buffer, int argc, char **argv)
{
    char *name, *jid = NULL, *password = NULL;

    (void) buffer;

    switch (argc)
    {
        case 5:
            password = argv[4];
            // fall through
        case 4:
            jid = argv[3];
            // fall through
        case 3:
            name = argv[2];
            command__add_account(name, jid, password);
            break;
        default:
            weechat_printf(NULL, _("account add: wrong number of arguments"));
            break;
    }
}

int command__connect_account(weechat::account *account)
{
    if (!account)
        return 0;

    if (account->connected())
    {
        weechat_printf(
            NULL,
            _("%s%s: already connected to account \"%s\"!"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            account->name.data());
    }

    account->connect();

    return 1;
}

int command__account_connect(struct t_gui_buffer *buffer, int argc, char **argv)
{
    int i, nb_connect, connect_ok;
    weechat::account *ptr_account = nullptr;

    (void) buffer;
    (void) argc;
    (void) argv;

    connect_ok = 1;

    nb_connect = 0;
    for (i = 2; i < argc; i++)
    {
        nb_connect++;
        if (weechat::account::search(ptr_account, argv[i]))
        {
            if (!command__connect_account(ptr_account))
            {
                connect_ok = 0;
            }
        }
        else
        {
            weechat_printf(
                NULL,
                _("%s%s: account not found \"%s\" "
                  "(add one first with: /account add)"),
                weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
                argv[i]);
        }
    }

    return (connect_ok) ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
}

int command__disconnect_account(weechat::account *account)
{
    if (!account)
        return 0;

    if (!account->connected())
    {
        weechat_printf(
            NULL,
            _("%s%s: not connected to account \"%s\"!"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            account->name.data());
    }

    account->disconnect(0);

    return 1;
}

int command__account_disconnect(struct t_gui_buffer *buffer, int argc, char **argv)
{
    int i, nb_disconnect, disconnect_ok;
    weechat::account *ptr_account;

    (void) argc;
    (void) argv;

    disconnect_ok = 1;

    nb_disconnect = 0;
    if (argc < 2)
    {
        weechat::channel *ptr_channel;

        buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

        if (ptr_account)
        {
            if (!command__disconnect_account(ptr_account))
            {
                disconnect_ok = 0;
            }
        }
    }
    for (i = 2; i < argc; i++)
    {
        nb_disconnect++;
        if (weechat::account::search(ptr_account, argv[i]))
        {
            if (!command__disconnect_account(ptr_account))
            {
                disconnect_ok = 0;
            }
        }
        else
        {
            weechat_printf(
                NULL,
                _("%s%s: account not found \"%s\" "),
                weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
                argv[i]);
        }
    }

    return (disconnect_ok) ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
}

int command__account_reconnect(struct t_gui_buffer *buffer, int argc, char **argv)
{
    command__account_disconnect(buffer, argc, argv);
    return command__account_connect(buffer, argc, argv);
}

void command__account_delete(struct t_gui_buffer *buffer, int argc, char **argv)
{
    (void) buffer;

    if (argc < 3)
    {
        weechat_printf(
            NULL,
            _("%sToo few arguments for command\"%s %s\" "
              "(help on command: /help %s)"),
            weechat_prefix("error"),
            argv[0], argv[1], argv[0] + 1);
        return;
    }

    weechat::account *account = nullptr;

    if (!weechat::account::search(account, argv[2]))
    {
        weechat_printf(
            NULL,
            _("%s%s: account \"%s\" not found for \"%s\" command"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            argv[2], "xmpp delete");
        return;
    }
    if (account->connected())
    {
        weechat_printf(
            NULL,
            _("%s%s: you cannot delete account \"%s\" because you"
              "are connected. Try \"/xmpp disconnect %s\" first."),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            argv[2], argv[2]);
        return;
    }

    std::string account_name = account->name;
    weechat::accounts.erase(account->name);
    weechat_printf(
        NULL,
        _("%s: account %s%s%s has been deleted"),
        WEECHAT_XMPP_PLUGIN_NAME,
        weechat_color("chat_server"),
        !account_name.empty() ? account_name.data() : "???",
        weechat_color("reset"));
}

int command__account(const void *pointer, void *data,
                     struct t_gui_buffer *buffer, int argc,
                     char **argv, char **argv_eol)
{

    (void) pointer;
    (void) data;
    (void) buffer;

    if (argc <= 1 || weechat_strcasecmp(argv[1], "list") == 0)
    {
        command__account_list(argc, argv);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        if (weechat_strcasecmp(argv[1], "add") == 0)
        {
            command__account_add(buffer, argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "connect") == 0)
        {
            command__account_connect(buffer, argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "disconnect") == 0)
        {
            command__account_disconnect(buffer, argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "reconnect") == 0)
        {
            command__account_reconnect(buffer, argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "delete") == 0)
        {
            command__account_delete(buffer, argc, argv);
            return WEECHAT_RC_OK;
        }

        WEECHAT_COMMAND_ERROR;
    }

    return WEECHAT_RC_OK;
}

int command__enter(const void *pointer, void *data,
                   struct t_gui_buffer *buffer, int argc,
                   char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    xmpp_stanza_t *pres;
    char *jid, *pres_jid, *text;

    (void) pointer;
    (void) data;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_account->connected())
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        int n_jid = 0;
        char **jids = weechat_string_split(argv[1], ",", NULL, 0, 0, &n_jid);
        for (int i = 0; i < n_jid; i++)
        {
            jid = xmpp_jid_bare(ptr_account->context, jids[i]);
            pres_jid = jids[i];

            if(!xmpp_jid_resource(ptr_account->context, pres_jid))
                pres_jid = xmpp_jid_new(
                    ptr_account->context,
                    xmpp_jid_node(ptr_account->context, jid),
                    xmpp_jid_domain(ptr_account->context, jid),
                    ptr_account->nickname().data()
                    && strlen(ptr_account->nickname().data())
                    ? ptr_account->nickname().data()
                    : xmpp_jid_node(ptr_account->context,
                                    ptr_account->jid().data()));

            if (!ptr_account->channels.contains(jid))
                ptr_channel = &ptr_account->channels.emplace(
                    std::make_pair(jid, weechat::channel {
                            *ptr_account, weechat::channel::chat_type::MUC, jid, jid
                        })).first->second;
	    if (!ptr_channel) {
		weechat_string_free_split(jids); // raii unique_ptr?
		return WEECHAT_RC_ERROR;
	    }

            pres = xmpp_presence_new(ptr_account->context);
            xmpp_stanza_set_to(pres, pres_jid);
            xmpp_stanza_set_from(pres, ptr_account->jid().data());

            xmpp_stanza_t *pres__x = xmpp_stanza_new(ptr_account->context);
            xmpp_stanza_set_name(pres__x, "x");
            xmpp_stanza_set_ns(pres__x, "http://jabber.org/protocol/muc");
            xmpp_stanza_add_child(pres, pres__x);
            xmpp_stanza_release(pres__x);

            xmpp_send(ptr_account->connection, pres);
            xmpp_stanza_release(pres);

            if (argc > 2)
            {
                text = argv_eol[2];

                ptr_channel->send_message(jid, text);
            }

            char buf[16];
            int num = weechat_buffer_get_integer(ptr_channel->buffer, "number");
            snprintf(buf, sizeof(buf), "/buffer %d", num);
            weechat_command(ptr_account->buffer, buf);
        }
        weechat_string_free_split(jids);
    }
    else
    {
        const char *buffer_jid = weechat_buffer_get_string(buffer, "localvar_remote_jid");

        pres_jid = xmpp_jid_new(
            ptr_account->context,
            xmpp_jid_node(ptr_account->context, buffer_jid),
            xmpp_jid_domain(ptr_account->context, buffer_jid),
            weechat_buffer_get_string(buffer, "localvar_nick"));

        if (!ptr_account->channels.contains(buffer_jid))
            ptr_channel = &ptr_account->channels.emplace(
                std::make_pair(jid, weechat::channel {
                        *ptr_account, weechat::channel::chat_type::MUC, buffer_jid, buffer_jid
                    })).first->second;

        pres = xmpp_presence_new(ptr_account->context);
        xmpp_stanza_set_to(pres, pres_jid);
        xmpp_stanza_set_from(pres, ptr_account->jid().data());

        xmpp_stanza_t *pres__x = xmpp_stanza_new(ptr_account->context);
        xmpp_stanza_set_name(pres__x, "x");
        xmpp_stanza_set_ns(pres__x, "http://jabber.org/protocol/muc");
        xmpp_stanza_add_child(pres, pres__x);
        xmpp_stanza_release(pres__x);

        xmpp_send(ptr_account->connection, pres);
        xmpp_stanza_release(pres);
    }

    return WEECHAT_RC_OK;
}

int command__open(const void *pointer, void *data,
                  struct t_gui_buffer *buffer, int argc,
                  char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    xmpp_stanza_t *pres;
    char *jid, *text;

    (void) pointer;
    (void) data;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_account->connected())
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        int n_jid = 0;
        char **jids = weechat_string_split(argv[1], ",", NULL, 0, 0, &n_jid);
        for (int i = 0; i < n_jid; i++)
        {
            jid = xmpp_jid_bare(ptr_account->context, jids[i]);
            if (ptr_channel && !strchr(jid, '@'))
            {
                jid = xmpp_jid_new(
                    ptr_account->context,
                    xmpp_jid_node(ptr_account->context, ptr_channel->name.data()),
                    xmpp_jid_domain(ptr_account->context, ptr_channel->name.data()),
                    jid);
            }

            pres = xmpp_presence_new(ptr_account->context);
            xmpp_stanza_set_to(pres, jid);
            xmpp_stanza_set_from(pres, ptr_account->jid().data());
            xmpp_send(ptr_account->connection, pres);
            xmpp_stanza_release(pres);

            auto channel = ptr_account->channels.find(jid);
            if (channel == ptr_account->channels.end())
                channel = ptr_account->channels.emplace(
                    std::make_pair(jid, weechat::channel {
                            *ptr_account, weechat::channel::chat_type::PM, jid, jid
                        })).first;

            if (argc > 2)
            {
                text = argv_eol[2];

                channel->second.send_message(jid, text);
            }

            char buf[16];
            int num = weechat_buffer_get_integer(channel->second.buffer, "number");
            snprintf(buf, sizeof(buf), "/buffer %d", num);
            weechat_command(ptr_account->buffer, buf);
        }
        weechat_string_free_split(jids);
    }

    return WEECHAT_RC_OK;
}

int command__msg(const void *pointer, void *data,
                 struct t_gui_buffer *buffer, int argc,
                 char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    xmpp_stanza_t *message;
    char *text;

    (void) pointer;
    (void) data;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf(
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "msg");
        return WEECHAT_RC_OK;
    }

    if (!ptr_account->connected())
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        text = argv_eol[1];

        message = xmpp_message_new(ptr_account->context,
                                   ptr_channel->type == weechat::channel::chat_type::MUC ? "groupchat" : "chat",
                                   ptr_channel->name.data(), NULL);
        xmpp_message_set_body(message, text);
        xmpp_send(ptr_account->connection, message);
        xmpp_stanza_release(message);
        if (ptr_channel->type != weechat::channel::chat_type::MUC)
            weechat_printf_date_tags(ptr_channel->buffer, 0,
                                     "xmpp_message,message,private,notify_none,self_msg,log1",
                                     "%s\t%s",
                                     weechat::user::search(ptr_account, ptr_account->jid().data())->as_prefix_raw().data(),
                                     text);
    }

    return WEECHAT_RC_OK;
}

int command__me(const void *pointer, void *data,
                struct t_gui_buffer *buffer, int argc,
                char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    xmpp_stanza_t *message;
    char *text;

    (void) pointer;
    (void) data;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf(
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "me");
        return WEECHAT_RC_OK;
    }

    if (!ptr_account->connected())
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        text = argv_eol[0];

        message = xmpp_message_new(ptr_account->context,
                                   ptr_channel->type == weechat::channel::chat_type::MUC ? "groupchat" : "chat",
                                   ptr_channel->name.data(), NULL);
        xmpp_message_set_body(message, text);
        xmpp_send(ptr_account->connection, message);
        xmpp_stanza_release(message);
        if (ptr_channel->type != weechat::channel::chat_type::MUC)
            weechat_printf_date_tags(ptr_channel->buffer, 0,
                                     "xmpp_message,message,action,private,notify_none,self_msg,log1",
                                     "%s%s %s",
                                     weechat_prefix("action"),
                                     weechat::user::search(ptr_account, ptr_account->jid().data())->as_prefix_raw().data(),
                                     strlen(text) > strlen("/me ") ? text+4 : "");
    }

    return WEECHAT_RC_OK;
}

int command__mam(const void *pointer, void *data,
                 struct t_gui_buffer *buffer, int argc,
                 char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    int days;

    (void) pointer;
    (void) data;
    (void) argv_eol;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf(
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "mam");
        return WEECHAT_RC_OK;
    }

    time_t start = time(NULL);
    struct tm *ago = gmtime(&start);
    if (argc > 1)
    {
        errno = 0;
        days = strtol(argv[1], NULL, 10);

        if (errno == 0)
            ago->tm_mday -= days;
        else
        {
            weechat_printf(
                ptr_channel->buffer,
                _("%s%s: \"%s\" is not a valid number of %s for %s"),
                weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "days", "mam");
            ago->tm_mday -= MAM_DEFAULT_DAYS;
        }
    }
    else
        ago->tm_mday -= MAM_DEFAULT_DAYS;
    start = mktime(ago);
    ptr_channel->fetch_mam(NULL, &start, NULL, NULL);

    return WEECHAT_RC_OK;
}

int command__omemo(const void *pointer, void *data,
                   struct t_gui_buffer *buffer, int argc,
                   char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;

    (void) pointer;
    (void) data;
    (void) argc;
    (void) argv;
    (void) argv_eol;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf(
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "omemo");
        return WEECHAT_RC_OK;
    }

    ptr_channel->omemo.enabled = 1;
    ptr_channel->pgp.enabled = 0;

    ptr_channel->set_transport(weechat::channel::transport::OMEMO, 0);

    return WEECHAT_RC_OK;
}

int command__pgp(const void *pointer, void *data,
                 struct t_gui_buffer *buffer, int argc,
                 char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    char *keyid;

    (void) pointer;
    (void) data;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf(
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "pgp");
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        keyid = argv_eol[1];

        ptr_channel->pgp.ids.emplace(keyid);
    }
    ptr_channel->omemo.enabled = 0;
    ptr_channel->pgp.enabled = 1;

    ptr_channel->set_transport(weechat::channel::transport::PGP, 0);

    return WEECHAT_RC_OK;
}

int command__plain(const void *pointer, void *data,
                   struct t_gui_buffer *buffer, int argc,
                   char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;

    (void) pointer;
    (void) data;
    (void) argc;
    (void) argv;
    (void) argv_eol;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf(
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "plain");
        return WEECHAT_RC_OK;
    }

    ptr_channel->omemo.enabled = 0;
    ptr_channel->pgp.enabled = 0;

    ptr_channel->set_transport(weechat::channel::transport::PLAIN, 0);

    return WEECHAT_RC_OK;
}

int command__xml(const void *pointer, void *data,
                 struct t_gui_buffer *buffer, int argc,
                 char **argv, char **argv_eol)
{
    weechat::account *ptr_account = NULL;
    weechat::channel *ptr_channel = NULL;
    xmpp_stanza_t *stanza;

    (void) pointer;
    (void) data;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_account->connected())
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        auto parse = [&](sexp::driver& sxml) {
            std::stringstream ss;
            std::string line;
            try {
                return sxml.parse(argv_eol[1], &ss);
            }
            catch (const std::invalid_argument& ex) {
                while (std::getline(ss, line))
                    weechat_printf(nullptr, "%ssxml: %s", weechat_prefix("info"), line.data());
                weechat_printf(nullptr, "%ssxml: %s", weechat_prefix("error"), ex.what());
                return false;
            }
        };
        if (sexp::driver sxml(ptr_account->context); parse(sxml))
        {
            for (auto *stanza : sxml.elements)
            {
                xmpp_send(ptr_account->connection, stanza);
                xmpp_stanza_release(stanza);
            }
        }
        else
        {
            stanza = xmpp_stanza_new_from_string(ptr_account->context,
                                                argv_eol[1]);
            if (!stanza)
            {
                weechat_printf(nullptr, _("%s%s: Bad XML"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
                return WEECHAT_RC_ERROR;
            }

            xmpp_send(ptr_account->connection, stanza);
            xmpp_stanza_release(stanza);
        }
    }

    return WEECHAT_RC_OK;
}

int command__xmpp(const void *pointer, void *data,
                  struct t_gui_buffer *buffer, int argc,
                  char **argv, char **argv_eol)
{
    (void) pointer;
    (void) data;
    (void) buffer;
    (void) argc;
    (void) argv;
    (void) argv_eol;

    weechat_printf(nullptr,
                   _("%s%s %s [%s]"),
                   weechat_prefix("info"), WEECHAT_XMPP_PLUGIN_NAME,
                   WEECHAT_XMPP_PLUGIN_VERSION, XMPP_PLUGIN_COMMIT);

    return WEECHAT_RC_OK;
}

int command__trap(const void *pointer, void *data,
                  struct t_gui_buffer *buffer, int argc,
                  char **argv, char **argv_eol)
{
    (void) pointer;
    (void) data;
    (void) buffer;
    (void) argc;
    (void) argv;
    (void) argv_eol;

    weechat::account *account = NULL;
    weechat::channel *channel = NULL;
    weechat::user *user = NULL;

    buffer__get_account_and_channel(buffer, &account, &channel);
    weechat::user::search(account, account->jid_device().data());

    __asm("int3");

    return WEECHAT_RC_OK;
}

void command__init()
{
    struct t_hook *hook;

    hook = weechat_hook_command(
        "account",
        N_("handle xmpp accounts"),
        N_("list"
           " || add <name> <jid> <password>"
           " || connect <account>"
           " || disconnect <account>"
           " || reconnect <account>"
           " || delete <account>"),
        N_("      list: list accounts\n"
           "       add: add a xmpp account\n"
           "   connect: connect to a xmpp account\n"
           "disconnect: disconnect from a xmpp account\n"
           " reconnect: reconnect an xmpp account\n"
           "    delete: delete a xmpp account\n"),
        "list"
        " || add %(xmpp_account)"
        " || connect %(xmpp_account)"
        " || disconnect %(xmpp_account)"
        " || reconnect %(xmpp_account)"
        " || delete %(xmpp_account)",
        &command__account, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /account");

    hook = weechat_hook_command(
        "enter",
        N_("enter an xmpp multi-user-chat (muc)"),
        N_("<jid>"),
        N_("jid: muc to enter"),
        NULL, &command__enter, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /enter");

    hook = weechat_hook_command(
        "open",
        N_("open a direct xmpp chat"),
        N_("<jid>"),
        N_("jid: jid to target, or nick from the current muc"),
        NULL, &command__open, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /open");

    hook = weechat_hook_command(
        "msg",
        N_("send a xmpp message to the current buffer"),
        N_("<message>"),
        N_("message: message to send"),
        NULL, &command__msg, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /msg");

    hook = weechat_hook_command(
        "me",
        N_("send a xmpp action to the current buffer"),
        N_("<message>"),
        N_("message: message to send"),
        NULL, &command__me, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /me");

    hook = weechat_hook_command(
        "mam",
        N_("retrieve mam messages for the current channel"),
        N_("[days]"),
        N_("days: number of days to fetch (default: " STR(MAM_DEFAULT_DAYS) ")"),
        NULL, &command__mam, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /mam");

    hook = weechat_hook_command(
        "omemo",
        N_("set the current buffer to use omemo encryption"),
        N_(""),
        N_(""),
        NULL, &command__omemo, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /omemo");

    hook = weechat_hook_command(
        "pgp",
        N_("set the current buffer to use pgp encryption (with a given target pgp key)"),
        N_("<keyid>"),
        N_("keyid: recipient keyid"),
        NULL, &command__pgp, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /pgp");

    hook = weechat_hook_command(
        "plain",
        N_("set the current buffer to use no encryption"),
        N_(""),
        N_(""),
        NULL, &command__plain, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /plain");

    hook = weechat_hook_command(
        "xml",
        N_("send a raw xml stanza"),
        N_("<stanza>"),
        N_("stanza: xml to send"),
        NULL, &command__xml, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /xml");

    hook = weechat_hook_command(
        "xmpp",
        N_("get xmpp plugin version (see /help for general help)"),
        N_(""),
        N_(""),
        NULL, &command__xmpp, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /xmpp");

    hook = weechat_hook_command(
        "trap",
        N_("debug trap (int3)"),
        N_(""),
        N_(""),
        NULL, &command__trap, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /trap");
}
