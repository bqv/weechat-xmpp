#include <stdlib.h>
#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-command.h"
#include "slack-oauth.h"
#include "slack-workspace.h"

void slack_command_display_workspace(struct t_slack_workspace *workspace)
{
    int num_channels, num_pv;

    if (workspace->is_connected)
    {
        num_channels = 0;//slack_workspace_get_channel_count(workspace);
        num_pv = 0;//slack_workspace_get_pv_count(workspace);
        weechat_printf(
            NULL,
            " %s %s%s %s[%s%s%s]%s, %d %s, %d pv",
            (workspace->is_connected) ? "*" : " ",
            weechat_color("chat_workspace"),
            workspace->name,
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
            "   %s%s%s",
            weechat_color("chat_workspace"),
            workspace->name,
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

void slack_command_add_workspace(char *token)
{
    free(token);
}

void slack_command_workspace_register(int argc, char **argv)
{
    char *code;

    if (argc > 2)
    {
        code = argv[2];
        
        if (weechat_strncasecmp("xoxp", code, 4) == 0)
        {
            slack_command_add_workspace(strdup(code));
        }
        else
        {
            slack_oauth_request_token(code, &slack_command_add_workspace);
        }
    }
    else
    {
        weechat_printf(NULL,
                       _("\n#### Retrieving a Slack token via OAUTH ####\n"
                         "1) Paste this into a browser: https://slack.com/oauth/authorize?client_id=%s&scope=client\n"
                         "2) Select the team you wish to access from wee-slack in your browser.\n"
                         "3) Click \"Authorize\" in the browser **IMPORTANT: the redirect will fail, this is expected**\n"
                         "4) Copy the \"code\" portion of the URL to your clipboard\n"
                         "5) Return to weechat and run `/slack register [code]`\n"),
                       SLACK_CLIENT_ID);
    }
}

void slack_command_workspace_delete(int argc, char **argv)
{
}

int slack_command_slack(const void *pointer, void *data,
                        struct t_gui_buffer *buffer, int argc,
                        char **argv, char **argv_eol)
{
    /* make C compiler happy */
    (void) pointer;
    (void) data;
    (void) buffer;

    if (argc > 1)
    {
        if (weechat_strcasecmp(argv[1], "list") == 0)
        {
            slack_command_workspace_list(argc, argv);
            return WEECHAT_RC_OK;
        }

        if (weechat_strcasecmp(argv[1], "register") == 0)
        {
            slack_command_workspace_register(argc, argv);
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

void slack_command_init()
{
    weechat_hook_command(
        "slack",
        N_("slack control"),
        N_("list"
           " || register [token]"
           " || delete <workspace>"),
        N_("    list: list workspaces\n"
           "register: add a slack workspace\n"
           "  delete: delete a slack workspace\n"),
        "list"
        " || register %(slack_token)"
        " || delete %(slack_workspace)",
        &slack_command_slack, NULL, NULL);
}
