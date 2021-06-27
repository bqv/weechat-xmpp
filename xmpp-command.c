// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <string.h>
#include <weechat/weechat-plugin.h>

#include "xmpp.h"
//#include "xmpp-oauth.h"
//#include "xmpp-teaminfo.h"
//#include "xmpp-workspace.h"
//#include "xmpp-channel.h"
//#include "xmpp-buffer.h"
//#include "xmpp-message.h"
#include "xmpp-command.h"
//#include "request/xmpp-request-chat-memessage.h"

/*
void xmpp_command_display_workspace(xmpp_conn_t *workspace)
{
    int num_channels, num_pv;

    if (workspace->is_connected)
    {
        num_channels = 0;//xmpp_workspace_get_channel_count(workspace);
        num_pv = 0;//xmpp_workspace_get_pv_count(workspace);
        weechat_printf(
            NULL,
            " %s %s%s%s.xmpp.com %s(%s%s%s) [%s%s%s]%s, %d %s, %d pv",
            (workspace->is_connected) ? "*" : " ",
            weechat_color("chat_server"),
            workspace->domain,
            weechat_color("reset"),
            weechat_color("chat_delimiters"),
            weechat_color("chat_server"),
            (workspace->name) ?
            workspace->name : "???",
            weechat_color("chat_delimiters"),
            weechat_color("reset"),
            (workspace->is_connected) ?
            _("connected") : _("not connected"),
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
            "   %s%s%s.xmpp.com %s(%s%s%s)%s",
            weechat_color("chat_server"),
            workspace->domain,
            weechat_color("reset"),
            weechat_color("chat_delimiters"),
            weechat_color("chat_server"),
            (workspace->name) ?
            workspace->name : "???",
            weechat_color("chat_delimiters"),
            weechat_color("reset"));
    }
}

void xmpp_command_workspace_list(int argc, char **argv)
{
    int i, one_workspace_found;
    xmpp_conn_t *ptr_workspace2;
    char *workspace_name = NULL;

    for (i = 2; i < argc; i++)
    {
        if (!workspace_name)
            workspace_name = argv[i];
    }
    if (!workspace_name)
    {
        if (xmpp_workspaces)
        {
            weechat_printf(NULL, "");
            weechat_printf(NULL, _("All workspaces:"));
            for (ptr_workspace2 = xmpp_workspaces; ptr_workspace2;
                 ptr_workspace2 = ptr_workspace2->next_workspace)
            {
                xmpp_command_display_workspace(ptr_workspace2);
            }
        }
        else
            weechat_printf(NULL, _("No workspace"));
    }
    else
    {
        one_workspace_found = 0;
        for (ptr_workspace2 = xmpp_workspaces; ptr_workspace2;
             ptr_workspace2 = ptr_workspace2->next_workspace)
        {
            if (weechat_strcasestr(ptr_workspace2->name, workspace_name))
            {
                if (!one_workspace_found)
                {
                    weechat_printf(NULL, "");
                    weechat_printf(NULL,
                                   _("Servers with \"%s\":"),
                                   workspace_name);
                }
                one_workspace_found = 1;
                xmpp_command_display_workspace(ptr_workspace2);
            }
        }
        if (!one_workspace_found)
            weechat_printf(NULL,
                           _("No workspace found with \"%s\""),
                           workspace_name);
    }
}

void xmpp_command_add_workspace(struct t_xmpp_teaminfo *xmpp_teaminfo)
{
    xmpp_conn_t *workspace;

    workspace = xmpp_workspace_casesearch(xmpp_teaminfo->domain);
    if (workspace)
    {
        weechat_printf(
            NULL,
            _("%s%s: workspace \"%s\" already exists, can't add it!"),
            weechat_prefix("error"), XMPP_PLUGIN_NAME,
            xmpp_teaminfo->domain);
        return;
    }

    workspace = xmpp_workspace_alloc(xmpp_teaminfo->domain);
    if (!workspace)
    {
        weechat_printf(
            NULL,
            _("%s%s: unable to add workspace"),
            weechat_prefix("error"), XMPP_PLUGIN_NAME);
        return;
    }

    workspace->id = strdup(xmpp_teaminfo->id);
    workspace->name = strdup(xmpp_teaminfo->name);
    weechat_config_option_set(workspace->options[XMPP_WORKSPACE_OPTION_TOKEN],
            xmpp_teaminfo->token, 1);

    weechat_printf (
        NULL,
        _("%s: workspace %s%s%s.xmpp.com %s(%s%s%s)%s added"),
        XMPP_PLUGIN_NAME,
        weechat_color("chat_server"),
        workspace->domain,
        weechat_color("reset"),
        weechat_color("chat_delimiters"),
        weechat_color("chat_server"),
        workspace->name,
        weechat_color("chat_delimiters"),
        weechat_color("reset"));

    free_teaminfo(xmpp_teaminfo);
}

void xmpp_command_fetch_workspace(char *token)
{
    xmpp_teaminfo_fetch(token, &xmpp_command_add_workspace);

    free(token);
}

void xmpp_command_workspace_register(int argc, char **argv)
{
    char *code;

    if (argc > 2)
    {
        code = argv[2];

        if (strncmp("xoxp", code, 4) == 0)
        {
            xmpp_command_fetch_workspace(strdup(code));
        }
        else
        {
            xmpp_oauth_request_token(code, &xmpp_command_fetch_workspace);
        }
    }
    else
    {
        weechat_printf(NULL,
                       _("\n#### Retrieving a Xmpp token via OAUTH ####\n"
                         "1) Paste this into a browser: https://xmpp.com/oauth/authorize?client_id=%s&scope=client\n"
                         "2) Select the team you wish to access from weechat in your browser.\n"
                         "3) Click \"Authorize\" in the browser **IMPORTANT: the redirect will fail, this is expected**\n"
                         "4) Copy the \"code\" portion of the URL to your clipboard\n"
                         "5) Return to weechat and run `/xmpp register [code]`\n"),
                       XMPP_CLIENT_ID);
    }
}

int xmpp_command_connect_workspace(xmpp_conn_t *workspace)
{
    if (!workspace)
        return 0;

    if (workspace->is_connected)
    {
        weechat_printf(
            NULL,
            _("%s%s: already connected to workspace \"%s\"!"),
            weechat_prefix("error"), XMPP_PLUGIN_NAME,
            workspace->domain);
    }

    xmpp_workspace_connect(workspace);

    return 1;
}

int xmpp_command_workspace_connect(int argc, char **argv)
{
    int i, nb_connect, connect_ok;
    xmpp_conn_t *ptr_workspace;

    (void) argc;
    (void) argv;

    connect_ok = 1;

    nb_connect = 0;
    for (i = 2; i < argc; i++)
    {
        nb_connect++;
        ptr_workspace = xmpp_workspace_search(argv[i]);
        if (ptr_workspace)
        {
            if (!xmpp_command_connect_workspace(ptr_workspace))
            {
                connect_ok = 0;
            }
        }
        else
        {
            weechat_printf(
                NULL,
                _("%s%s: workspace not found \"%s\" "
                  "(register first with: /xmpp register)"),
                weechat_prefix("error"), XMPP_PLUGIN_NAME,
                argv[i]);
        }
    }

    return (connect_ok) ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
}

void xmpp_command_workspace_delete(int argc, char **argv)
{
    xmpp_conn_t *workspace;
    char *workspace_domain;

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

    workspace = xmpp_workspace_search(argv[2]);
    if (!workspace)
    {
        weechat_printf(
            NULL,
            _("%s%s: workspace \"%s\" not found for \"%s\" command"),
            weechat_prefix("error"), XMPP_PLUGIN_NAME,
            argv[2], "xmpp delete");
        return;
    }
    if (workspace->is_connected)
    {
        weechat_printf(
            NULL,
            _("%s%s: you cannot delete workspace \"%s\" because you"
              "are connected. Try \"/xmpp disconnect %s\" first."),
            weechat_prefix("error"), XMPP_PLUGIN_NAME,
            argv[2], argv[2]);
        return;
    }

    workspace_domain = strdup(workspace->domain);
    xmpp_workspace_free(workspace);
    weechat_printf (
        NULL,
        _("%s: workspace %s%s%s has been deleted"),
        XMPP_PLUGIN_NAME,
        weechat_color("chat_server"),
        (workspace_domain) ? workspace_domain : "???",
        weechat_color("reset"));
    if (workspace_domain)
        free(workspace_domain);
}
*/

int xmpp_command_xmpp(const void *pointer, void *data,
                        struct t_gui_buffer *buffer, int argc,
                        char **argv, char **argv_eol)
{

    (void) pointer;
    (void) data;
    (void) buffer;

  //if (argc <= 1 || weechat_strcasecmp(argv[1], "list") == 0)
  //{
  //    xmpp_command_workspace_list(argc, argv);
  //    return WEECHAT_RC_OK;
  //}

  //if (argc > 1)
  //{
  //    if (weechat_strcasecmp(argv[1], "register") == 0)
  //    {
  //        xmpp_command_workspace_register(argc, argv);
  //        return WEECHAT_RC_OK;
  //    }

  //    if (weechat_strcasecmp(argv[1], "connect") == 0)
  //    {
  //        xmpp_command_workspace_connect(argc, argv);
  //        return WEECHAT_RC_OK;
  //    }

  //    if (weechat_strcasecmp(argv[1], "delete") == 0)
  //    {
  //        xmpp_command_workspace_delete(argc, argv);
  //        return WEECHAT_RC_OK;
  //    }

  //    WEECHAT_COMMAND_ERROR;
  //}

    return WEECHAT_RC_OK;
}

int xmpp_command_me(const void *pointer, void *data,
                     struct t_gui_buffer *buffer, int argc,
                     char **argv, char **argv_eol)
{
    xmpp_conn_t *ptr_workspace = NULL;
  //struct t_xmpp_channel *ptr_channel = NULL;
  //struct t_xmpp_request *request;
    char *text;

    (void) pointer;
    (void) data;
    (void) buffer;
    (void) argv;

  //xmpp_buffer_get_workspace_and_channel(buffer, &ptr_workspace, &ptr_channel);

  //if (!ptr_workspace)
  //    return WEECHAT_RC_ERROR;

  //if (!ptr_channel)
  //{
  //    weechat_printf (
  //        ptr_workspace->buffer,
  //        _("%s%s: \"%s\" command can not be executed on a workspace buffer"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME, "me");
  //    return WEECHAT_RC_OK;
  //}

  //if (!ptr_workspace->is_connected)
  //{
  //    weechat_printf(buffer,
  //                    _("%s%s: you are not connected to server"),
  //                    weechat_prefix("error"), XMPP_PLUGIN_NAME);
  //    return WEECHAT_RC_OK;
  //}

  //if (argc > 1)
  //{
  //    text = malloc(XMPP_MESSAGE_MAX_LENGTH);
  //    if (!text)
  //    {
  //        weechat_printf(buffer,
  //                        _("%s%s: error allocating string"),
  //                        weechat_prefix("error"), XMPP_PLUGIN_NAME);
  //        return WEECHAT_RC_ERROR;
  //    }
  //    lws_urlencode(text, argv_eol[1], XMPP_MESSAGE_MAX_LENGTH);

  //    request = xmpp_request_chat_memessage(ptr_workspace,
  //                weechat_config_string(
  //                    ptr_workspace->options[XMPP_WORKSPACE_OPTION_TOKEN]),
  //                ptr_channel->id, text);
  //    if (request)
  //        xmpp_workspace_register_request(ptr_workspace, request);

  //    free(text);
  //}

    return WEECHAT_RC_OK;
}

void xmpp_command_init()
{
    weechat_hook_command(
        "xmpp",
        N_("xmpp control"),
        N_("list"
           " || register [token]"
           " || connect <workspace>"
           " || delete <workspace>"),
        N_("    list: list workspaces\n"
           "register: add a xmpp workspace\n"
           " connect: connect to a xmpp workspace\n"
           "  delete: delete a xmpp workspace\n"),
        "list"
        " || register %(xmpp_token)"
        " || connect %(xmpp_workspace)"
        " || delete %(xmpp_workspace)",
        &xmpp_command_xmpp, NULL, NULL);

    weechat_hook_command(
        "me",
        N_("send a xmpp action to the current channel"),
        N_("<message>"),
        N_("message: message to send"),
        NULL, &xmpp_command_me, NULL, NULL);
}
