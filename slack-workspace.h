#ifndef _SLACK_WORKSPACE_H_
#define _SLACK_WORKSPACE_H_

extern struct t_slack_workspace *slack_workspaces;
extern struct t_slack_workspace *last_slack_workspace;

enum t_slack_workspace_option
{
    SLACK_WORKSPACE_OPTION_TOKEN = 0,
    SLACK_WORKSPACE_NUM_OPTIONS,
};

struct t_json_chunk
{
    char *data;
    struct t_json_chunk *next;
};

struct t_slack_workspace
{
    char *id;
    char *name;
    char *domain;
    struct t_config_option *options[SLACK_WORKSPACE_NUM_OPTIONS];

	int reloading_from_config;
	int reloaded_from_config;

	int is_connected;
	int disconnected;

    char *uri;
    char *ws_url;
    struct lws *client_wsi;
    struct lws_context *context;
    struct t_json_chunk *json_chunks;

    char *user;
    char *nick;

	struct t_gui_buffer *buffer;
    char *buffer_as_string;
	struct t_slack_workspace *prev_workspace;
    struct t_slack_workspace *next_workspace;
};

extern char *slack_workspace_options[][2]; 

struct t_slack_workspace *slack_workspace_search(const char *workspace_domain);
struct t_slack_workspace *slack_workspace_casesearch (const char *workspace_domain);
int slack_workspace_search_option(const char *option_name);
struct t_slack_workspace *slack_workspace_alloc(const char *domain);
void slack_workspace_free_data(struct t_slack_workspace *workspace);
void slack_workspace_free(struct t_slack_workspace *workspace);
void slack_workspace_free_all();
void slack_workspace_disconnect(struct t_slack_workspace *workspace,
								int switch_address, int reconnect);
void slack_workspace_disconnect_all();
void slack_workspace_close_connection(struct t_slack_workspace *workspace);
int slack_workspace_connect(struct t_slack_workspace *workspace);
int slack_workspace_timer_cb(const void *pointer, void *data, int remaining_calls);

#endif /*SLACK_WORKSPACE_H*/
