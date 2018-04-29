#ifndef _SLACK_WORKSPACE_H_
#define _SLACK_WORKSPACE_H_

extern struct t_slack_workspace *slack_workspaces;
extern struct t_slack_workspace *last_slack_workspace;

enum t_slack_workspace_option
{
    SLACK_WORKSPACE_OPTION_TOKEN = 0,
    SLACK_WORKSPACE_NUM_OPTIONS,
};

struct t_slack_workspace
{
    char *name;
    struct t_config_option *options[SLACK_WORKSPACE_NUM_OPTIONS];

	int reloading_from_config;
	int reloaded_from_config;

	int is_connected;

	struct t_slack_workspace *prev_workspace;
    struct t_slack_workspace *next_workspace;
};

extern char *slack_workspace_options[][2]; 

struct t_slack_workspace *slack_workspace_search(const char *workspace_name);
int slack_workspace_search_option(const char *option_name);
struct t_slack_workspace *slack_workspace_alloc(const char *name);

#endif /*SLACK_WORKSPACE_H*/
