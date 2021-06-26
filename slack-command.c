// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-oauth.h"
#include "slack-teaminfo.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-buffer.h"
#include "slack-message.h"
#include "slack-command.h"
#include "request/slack-request-chat-memessage.h"

void slack_command_display_workspace(struct t_slack_workspace *workspace)
{
    int num_channels, num_pv;

    if (workspace->is_connected)
    {
        num_channels = 0;//slack_workspace_get_channel_count(workspace);
        num_pv = 0;//slack_workspace_get_pv_count(workspace);
        weechat_printf(
            NULL,
            " %s %s%s%s.slack.com %s(%s%s%s) [%s%s%s]%s, %d %s, %d pv",
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
            "   %s%s%s.slack.com %s(%s%s%s)%s",
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

void slack_command_workspace_list(int argc, char **argv)
{
    int i, one_workspace_found;
    struct t_slack_workspace *ptr_workspace2;
    char *workspace_name = NULL;

    for (i = 2; i < argc; i++)
    {
        if (!workspace_name)
            workspace_name = argv[i];
    }
    if (!workspace_name)
    {
        if (slack_workspaces)
        {
            weechat_printf(NULL, "");
            weechat_printf(NULL, _("All workspaces:"));
            for (ptr_workspace2 = slack_workspaces; ptr_workspace2;
                 ptr_workspace2 = ptr_workspace2->next_workspace)
            {
                slack_command_display_workspace(ptr_workspace2);
            }
        }
        else
            weechat_printf(NULL, _("No workspace"));
    }
    else
    {
        one_workspace_found = 0;
        for (ptr_workspace2 = slack_workspaces; ptr_workspace2;
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
                slack_command_display_workspace(ptr_workspace2);
            }
        }
        if (!one_workspace_found)
            weechat_printf(NULL,
                           _("No workspace found with \"%s\""),
                           workspace_name);
    }
}

void slack_command_add_workspace(struct t_slack_teaminfo *slack_teaminfo)
{
    struct t_slack_workspace *workspace;

    workspace = slack_workspace_casesearch(slack_teaminfo->domain);
    if (workspace)
    {
        weechat_printf(
            NULL,
            _("%s%s: workspace \"%s\" already exists, can't add it!"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            slack_teaminfo->domain);
        return;
    }

    workspace = slack_workspace_alloc(slack_teaminfo->domain);
    if (!workspace)
    {
        weechat_printf(
            NULL,
            _("%s%s: unable to add workspace"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return;
    }

    workspace->id = strdup(slack_teaminfo->id);
    workspace->name = strdup(slack_teaminfo->name);
    weechat_config_option_set(workspace->options[SLACK_WORKSPACE_OPTION_TOKEN],
            slack_teaminfo->token, 1);

    weechat_printf (
        NULL,
        _("%s: workspace %s%s%s.slack.com %s(%s%s%s)%s added"),
        SLACK_PLUGIN_NAME,
        weechat_color("chat_server"),
        workspace->domain,
        weechat_color("reset"),
        weechat_color("chat_delimiters"),
        weechat_color("chat_server"),
        workspace->name,
        weechat_color("chat_delimiters"),
        weechat_color("reset"));

    free_teaminfo(slack_teaminfo);
}

void slack_command_fetch_workspace(char *token)
{
    slack_teaminfo_fetch(token, &slack_command_add_workspace);

    free(token);
}

void slack_command_workspace_register(int argc, char **argv)
{
    char *code;

    if (argc > 2)
    {
        code = argv[2];
        
        if (strncmp("xoxp", code, 4) == 0)
        {
            slack_command_fetch_workspace(strdup(code));
        }
        else
        {
            slack_oauth_request_token(code, &slack_command_fetch_workspace);
        }
    }
    else
    {
        weechat_printf(NULL,
                       _("\n#### Retrieving a Slack token via OAUTH ####\n"
                         "1) Paste this into a browser: https://slack.com/oauth/authorize?client_id=%s&scope=client\n"
                         "2) Select the team you wish to access from weechat in your browser.\n"
                         "3) Click \"Authorize\" in the browser **IMPORTANT: the redirect will fail, this is expected**\n"
                         "4) Copy the \"code\" portion of the URL to your clipboard\n"
                         "5) Return to weechat and run `/slack register [code]`\n"),
                       SLACK_CLIENT_ID);
    }
}

int slack_command_connect_workspace(struct t_slack_workspace *workspace)
{
    if (!workspace)
        return 0;

    if (workspace->is_connected)
    {
        weechat_printf(
            NULL,
            _("%s%s: already connected to workspace \"%s\"!"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            workspace->domain);
    }

    slack_workspace_connect(workspace);

    return 1;
}

int slack_command_workspace_connect(int argc, char **argv)
{
    int i, nb_connect, connect_ok;
    struct t_slack_workspace *ptr_workspace;

    (void) argc;
    (void) argv;

    connect_ok = 1;

    nb_connect = 0;
    for (i = 2; i < argc; i++)
    {
        nb_connect++;
        ptr_workspace = slack_workspace_search(argv[i]);
        if (ptr_workspace)
        {
            if (!slack_command_connect_workspace(ptr_workspace))
            {
                connect_ok = 0;
            }
        }
        else
        {
            weechat_printf(
                NULL,
                _("%s%s: workspace not found \"%s\" "
                  "(register first with: /slack register)"),
                weechat_prefix("error"), SLACK_PLUGIN_NAME,
                argv[i]);
        }
    }

    return (connect_ok) ? WEECHAT_RC_OK : WEECHAT_RC_ERROR;
}

void slack_command_workspace_delete(int argc, char **argv)
{
    struct t_slack_workspace *workspace;
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

    workspace = slack_workspace_search(argv[2]);
    if (!workspace)
    {
        weechat_printf(
            NULL,
            _("%s%s: workspace \"%s\" not found for \"%s\" command"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            argv[2], "slack delete");
        return;
    }
    if (workspace->is_connected)
    {
        weechat_printf(
            NULL,
            _("%s%s: you cannot delete workspace \"%s\" because you"
              "are connected. Try \"/slack disconnect %s\" first."),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            argv[2], argv[2]);
        return;
    }

    workspace_domain = strdup(workspace->domain);
    slack_workspace_free(workspace);
    weechat_printf (
        NULL,
        _("%s: workspace %s%s%s has been deleted"),
        SLACK_PLUGIN_NAME,
        weechat_color("chat_server"),
        (workspace_domain) ? workspace_domain : "???",
        weechat_color("reset"));
    if (workspace_domain)
        free(workspace_domain);
}

int slack_command_slack(const void *pointer, void *data,
                        struct t_gui_buffer *buffer, int argc,
                        char **argv, char **argv_eol)
{
    
    (void) pointer;
    (void) data;
    (void) buffer;

    if (argc <= 1 || weechat_strcasecmp(argv[1], "list") == 0)
    {
        slack_command_workspace_list(argc, argv);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        if (weechat_strcasecmp(argv[1], "register") == 0)
        {
            slack_command_workspace_register(argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "connect") == 0)
        {
            slack_command_workspace_connect(argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "delete") == 0)
        {
            slack_command_workspace_delete(argc, argv);
            return WEECHAT_RC_OK;
        }

        WEECHAT_COMMAND_ERROR;
    }

    return WEECHAT_RC_OK;
}

int slack_command_me(const void *pointer, void *data,
                     struct t_gui_buffer *buffer, int argc,
                     char **argv, char **argv_eol)
{
    struct t_slack_workspace *ptr_workspace = NULL;
    struct t_slack_channel *ptr_channel = NULL;
    struct t_slack_request *request;
    char *text;
    
    
    (void) pointer;
    (void) data;
    (void) buffer;
    (void) argv;

    slack_buffer_get_workspace_and_channel(buffer, &ptr_workspace, &ptr_channel);
    
    if (!ptr_workspace)
        return WEECHAT_RC_ERROR;

    if (!ptr_channel)
    {
        weechat_printf (
            ptr_workspace->buffer,
            _("%s%s: \"%s\" command can not be executed on a workspace buffer"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME, "me");
        return WEECHAT_RC_OK;
    }

    if (!ptr_workspace->is_connected)
    {
        weechat_printf(buffer,
                        _("%s%s: you are not connected to server"),
                        weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return WEECHAT_RC_OK;
    }

    if (argc > 1)
    {
        text = malloc(SLACK_MESSAGE_MAX_LENGTH);
        if (!text)
        {
            weechat_printf(buffer,
                            _("%s%s: error allocating string"),
                            weechat_prefix("error"), SLACK_PLUGIN_NAME);
            return WEECHAT_RC_ERROR;
        }
        lws_urlencode(text, argv_eol[1], SLACK_MESSAGE_MAX_LENGTH);

        request = slack_request_chat_memessage(ptr_workspace,
                    weechat_config_string(
                        ptr_workspace->options[SLACK_WORKSPACE_OPTION_TOKEN]),
                    ptr_channel->id, text);
        if (request)
            slack_workspace_register_request(ptr_workspace, request);

        free(text);
    }

    return WEECHAT_RC_OK;
}

void slack_command_init()
{
    weechat_hook_command(
        "slack",
        N_("slack control"),
        N_("list"
           " || register [token]"
           " || connect <workspace>"
           " || delete <workspace>"),
        N_("    list: list workspaces\n"
           "register: add a slack workspace\n"
           " connect: connect to a slack workspace\n"
           "  delete: delete a slack workspace\n"),
        "list"
        " || register %(slack_token)"
        " || connect %(slack_workspace)"
        " || delete %(slack_workspace)",
        &slack_command_slack, NULL, NULL);

    weechat_hook_command(
        "me",
        N_("send a slack action to the current channel"),
        N_("<message>"),
        N_("message: message to send"),
        NULL, &slack_command_me, NULL, NULL);
}
