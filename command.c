// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <string.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
//#include "oauth.h"
//#include "teaminfo.h"
#include "account.h"
#include "channel.h"
#include "buffer.h"
#include "message.h"
#include "command.h"

void command__display_account(struct t_account *account)
{
    int num_channels, num_pv;

    if (account->is_connected)
    {
        num_channels = 0;//xmpp_account_get_channel_count(account);
        num_pv = 0;//xmpp_account_get_pv_count(account);
        weechat_printf(
            NULL,
            " %s %s%s%s %s(%s%s%s) [%s%s%s]%s, %d %s, %d pv",
            (account->is_connected) ? "*" : " ",
            weechat_color("chat_server"),
            account->name,
            weechat_color("reset"),
            weechat_color("chat_delimiters"),
            weechat_color("chat_server"),
            (account->jid) ? account->jid : "???",
            weechat_color("chat_delimiters"),
            weechat_color("reset"),
            (account->is_connected) ? _("connected") : _("not connected"),
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
            account->name,
            weechat_color("reset"),
            weechat_color("chat_delimiters"),
            weechat_color("chat_server"),
            (account->jid) ? account->jid : "???",
            weechat_color("chat_delimiters"),
            weechat_color("reset"));
    }
}

void command__account_list(int argc, char **argv)
{
    int i, one_account_found;
    struct t_account *ptr_account2;
    char *account_name = NULL;

    for (i = 2; i < argc; i++)
    {
        if (!account_name)
            account_name = argv[i];
    }
    if (!account_name)
    {
        if (accounts)
        {
            weechat_printf(NULL, "");
            weechat_printf(NULL, _("All accounts:"));
            for (ptr_account2 = accounts; ptr_account2;
                 ptr_account2 = ptr_account2->next_account)
            {
                command__display_account(ptr_account2);
            }
        }
        else
            weechat_printf(NULL, _("No account"));
    }
    else
    {
        one_account_found = 0;
        for (ptr_account2 = accounts; ptr_account2;
             ptr_account2 = ptr_account2->next_account)
        {
            if (weechat_strcasestr(ptr_account2->name, account_name))
            {
                if (!one_account_found)
                {
                    weechat_printf(NULL, "");
                    weechat_printf(NULL,
                                   _("Servers with \"%s\":"),
                                   account_name);
                }
                one_account_found = 1;
                command__display_account(ptr_account2);
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
    struct t_account *account;

    account = account__casesearch(name);
    if (account)
    {
        weechat_printf(
            NULL,
            _("%s%s: account \"%s\" already exists, can't add it!"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            name);
        return;
    }

    account = account__alloc(name);
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
        account->jid = strdup(jid);
    if (password)
        account->password = strdup(password);
    weechat_config_option_set(account->options[ACCOUNT_OPTION_JID],
                              account->jid, 1);
    weechat_config_option_set(account->options[ACCOUNT_OPTION_PASSWORD],
                              account->password, 1);
    weechat_config_option_set(account->options[ACCOUNT_OPTION_NICKNAME],
                              account->jid ? xmpp_jid_node(account->context,
                                                           account->jid)
                              : NULL, 1);

    weechat_printf (
        NULL,
        _("%s: account %s%s%s %s(%s%s%s)%s added"),
        WEECHAT_XMPP_PLUGIN_NAME,
        weechat_color("chat_server"),
        account->name,
        weechat_color("reset"),
        weechat_color("chat_delimiters"),
        weechat_color("chat_server"),
        account->jid ? account->jid : "???",
        weechat_color("chat_delimiters"),
        weechat_color("reset"));
}

void command__account_add(int argc, char **argv)
{
    char *name, *jid = NULL, *password = NULL;

    switch (argc)
    {
        case 5:
            password = argv[4];
        case 4:
            jid = argv[3];
        case 3:
            name = argv[2];
            command__add_account(name, jid, password);
            break;
        default:
            weechat_printf(NULL, _("account add: wrong number of arguments"));
            break;
    }
}

int command__connect_account(struct t_account *account)
{
    if (!account)
        return 0;

    if (account->is_connected)
    {
        weechat_printf(
            NULL,
            _("%s%s: already connected to account \"%s\"!"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            account->name);
    }

    account__connect(account);

    return 1;
}

int command__account_connect(int argc, char **argv)
{
    int i, nb_connect, connect_ok;
    struct t_account *ptr_account;

    (void) argc;
    (void) argv;

    connect_ok = 1;

    nb_connect = 0;
    for (i = 2; i < argc; i++)
    {
        nb_connect++;
        ptr_account = account__search(argv[i]);
        if (ptr_account)
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

void command__account_delete(int argc, char **argv)
{
    struct t_account *account;
    char *account_name;

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

    account = account__search(argv[2]);
    if (!account)
    {
        weechat_printf(
            NULL,
            _("%s%s: account \"%s\" not found for \"%s\" command"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            argv[2], "xmpp delete");
        return;
    }
    if (account->is_connected)
    {
        weechat_printf(
            NULL,
            _("%s%s: you cannot delete account \"%s\" because you"
              "are connected. Try \"/xmpp disconnect %s\" first."),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            argv[2], argv[2]);
        return;
    }

    account_name = strdup(account->name);
    account__free(account);
    weechat_printf (
        NULL,
        _("%s: account %s%s%s has been deleted"),
        WEECHAT_XMPP_PLUGIN_NAME,
        weechat_color("chat_server"),
        (account_name) ? account_name : "???",
        weechat_color("reset"));
    if (account_name)
        free(account_name);
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
            command__account_add(argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "connect") == 0)
        {
            command__account_connect(argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "delete") == 0)
        {
            command__account_delete(argc, argv);
            return WEECHAT_RC_OK;
        }

        WEECHAT_COMMAND_ERROR;
    }

    return WEECHAT_RC_OK;
}

int command__me(const void *pointer, void *data,
               struct t_gui_buffer *buffer, int argc,
               char **argv, char **argv_eol)
{
    struct t_account *ptr_account = NULL;
    struct t_xmpp_channel *ptr_channel = NULL;
  //struct t_xmpp_request *request;
    char *text;

    (void) pointer;
    (void) data;
    (void) buffer;
    (void) argv;

    buffer__get_account_and_channel(buffer, &ptr_account, &ptr_channel);

    if (!ptr_account)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf (
            ptr_account->buffer,
            _("%s%s: \"%s\" command can not be executed on a account buffer"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, "me");
        return WEECHAT_RC_OK;
    }

    if (!ptr_account->is_connected)
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        text = argv_eol[1];

      //request = xmpp_request_chat_memessage(ptr_account,
      //            weechat_config_string(
      //                ptr_account->options[XMPP_ACCOUNT_OPTION_TOKEN]),
      //            ptr_channel->id, text);
      //if (request)
      //    xmpp_account_register_request(ptr_account, request);
    }

    return WEECHAT_RC_OK;
}

void command__init()
{
    struct t_hook *hook;

    hook = weechat_hook_command(
        "account",
        N_("handle xmpp accounts"),
        N_("list"
           " || add <account>"
           " || connect <account>"
           " || delete <account>"),
        N_("    list: list accounts\n"
           "    add: add a xmpp account\n"
           "connect: connect to a xmpp account\n"
           " delete: delete a xmpp account\n"),
        "list"
        " || add %(xmpp_account)"
        " || connect %(xmpp_account)"
        " || delete %(xmpp_account)",
        &command__account, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /account");

    hook = weechat_hook_command(
        "me",
        N_("send a xmpp action to the current channel"),
        N_("<message>"),
        N_("message: message to send"),
        NULL, &command__me, NULL, NULL);
    if (!hook)
        weechat_printf(NULL, "Failed to setup command /me");
}
