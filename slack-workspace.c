#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-config.h"
#include "slack-workspace.h"

struct t_slack_workspace *slack_workspaces = NULL;
struct t_slack_workspace *last_slack_workspace = NULL;

char *slack_workspace_options[SLACK_WORKSPACE_NUM_OPTIONS][2] =
{ { "token", "" },
};

struct t_slack_workspace *slack_workspace_search(const char *workspace_name)
{
    struct t_slack_workspace *ptr_workspace;

    if (!workspace_name)
        return NULL;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        if (strcmp(ptr_workspace->name, workspace_name) == 0)
            return ptr_workspace;
    }

    /* workspace not found */
    return NULL;
}

struct t_slack_workspace *slack_workspace_casesearch (const char *workspace_name)
{
    struct t_slack_workspace *ptr_workspace;

    if (!workspace_name)
        return NULL;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        if (weechat_strcasecmp (ptr_workspace->name, workspace_name) == 0)
            return ptr_workspace;
    }

    /* workspace not found */
    return NULL;
}

int slack_workspace_search_option(const char *option_name)
{
    int i;

    if (!option_name)
        return -1;

    for (i = 0; i < SLACK_WORKSPACE_NUM_OPTIONS; i++)
    {
        if (weechat_strcasecmp(slack_workspace_options[i][0], option_name) == 0)
            return i;
    }

    /* workspace option not found */
    return -1;
}

struct t_slack_workspace *slack_workspace_alloc(const char *name)
{
    struct t_slack_workspace *new_workspace;
    int i, length;
    char *option_name;

    if (slack_workspace_casesearch(name))
        return NULL;

    /* alloc memory for new workspace */
    new_workspace = malloc(sizeof(*new_workspace));
    if (!new_workspace)
    {
        weechat_printf(NULL,
                        _("%s%s: error when allocating new workspace"),
                        weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return NULL;
    }

    /* add new workspace to queue */
    new_workspace->prev_workspace = last_slack_workspace;
    new_workspace->next_workspace = NULL;
    if (last_slack_workspace)
        last_slack_workspace->next_workspace = new_workspace;
    else
        slack_workspaces = new_workspace;
    last_slack_workspace = new_workspace;

    /* set name */
    new_workspace->name = strdup(name);

    /* internal vars */
    new_workspace->reloading_from_config = 0;
    new_workspace->reloaded_from_config = 0;

    new_workspace->is_connected = 0;

    /* create options with null value */
    for (i = 0; i < SLACK_WORKSPACE_NUM_OPTIONS; i++)
    {
        length = strlen(new_workspace->name) + 1 +
            strlen(slack_workspace_options[i][0]) +
            512 +  /* inherited option name(slack.workspace_default.xxx) */
            1;
        option_name = malloc(length);
        if (option_name)
        {
            snprintf(option_name, length, "%s.%s << slack.workspace_default.%s",
                     new_workspace->name,
                     slack_workspace_options[i][0],
                     slack_workspace_options[i][0]);
            new_workspace->options[i] = slack_config_workspace_new_option(
                slack_config_file,
                slack_config_section_workspace,
                i,
                option_name,
                NULL,
                NULL,
                1,
                &slack_config_workspace_check_value_cb,
                slack_workspace_options[i][0],
                NULL,
                &slack_config_workspace_change_cb,
                slack_workspace_options[i][0],
                NULL);
            slack_config_workspace_change_cb(slack_workspace_options[i][0], NULL,
                                             new_workspace->options[i]);
            free(option_name);
        }
    }

    return new_workspace;
}
