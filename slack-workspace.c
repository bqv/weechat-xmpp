#include <libwebsockets.h>
#include <json.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-config.h"
#include "slack-input.h"
#include "slack-workspace.h"
#include "slack-api.h"
#include "slack-request.h"
#include "slack-user.h"
#include "slack-channel.h"
#include "slack-buffer.h"

struct t_slack_workspace *slack_workspaces = NULL;
struct t_slack_workspace *last_slack_workspace = NULL;

char *slack_workspace_options[SLACK_WORKSPACE_NUM_OPTIONS][2] =
{ { "token", "" },
};

static const char *const endpoint = "/api/rtm.connect?"
    "token=%s&batch_presence_aware=true&presence_sub=false&";

static inline int json_valid(json_object *object, struct t_slack_workspace *workspace)
{
    if (!object)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error requesting websocket: unexpected response from server"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return 0;
    }

    return 1;
}

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len)
{
    struct t_slack_workspace *workspace = (struct t_slack_workspace *)user;
    int status;

    switch (reason)
    {
    /* because we are protocols[0] ... */
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        weechat_printf(
            workspace->buffer,
            _("%s%s: error connecting to slack: %s"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            in ? (char *)in : "(null)");
        workspace->client_wsi = NULL;
        break;

    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        status = lws_http_client_http_response(wsi);
        weechat_printf(
            workspace->buffer,
            _("%s%s: requesting a websocket... (%d)"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME,
            status);
        break;

    /* chunks of chunked content, with header removed */
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
        {
            struct t_json_chunk *new_chunk, *last_chunk;

            new_chunk = malloc(sizeof(*new_chunk));
            new_chunk->data = malloc((1024 * sizeof(char)) + 1);
            new_chunk->data[0] = '\0';
            new_chunk->next = NULL;

            strncat(new_chunk->data, in, (int)len);

            if (workspace->json_chunks)
            {
                for (last_chunk = workspace->json_chunks; last_chunk->next;
                     last_chunk = last_chunk->next);
                last_chunk->next = new_chunk;
            }
            else
            {
                workspace->json_chunks = new_chunk;
            }
        }
        return 0; /* don't passthru */

    /* uninterpreted http content */
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
        {
            char buffer[1024 + LWS_PRE];
            char *px = buffer + LWS_PRE;
            int lenx = sizeof(buffer) - LWS_PRE;

            if (lws_http_client_read(wsi, &px, &lenx) < 0)
                return -1;
        }
        return 0; /* don't passthru */

    case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
        {
            int chunk_count, i;
            char *json_string;
            json_object *response, *ok, *error, *self, *team, *url;
            json_object *id, *name, *domain;
            struct t_json_chunk *chunk_ptr;

            chunk_count = 0;
            if (workspace->json_chunks)
            {
                chunk_count++;
                for (chunk_ptr = workspace->json_chunks; chunk_ptr->next;
                     chunk_ptr = chunk_ptr->next)
                {
                    chunk_count++;
                }
            }

            json_string = malloc((1024 * sizeof(char) * chunk_count) + 1);
            json_string[0] = '\0';

            chunk_ptr = workspace->json_chunks;
            for (i = 0; i < chunk_count; i++)
            {
                strncat(json_string, chunk_ptr->data, 1024);
                chunk_ptr = chunk_ptr->next;

                free(workspace->json_chunks->data);
                free(workspace->json_chunks);
                workspace->json_chunks = chunk_ptr;
            }

            weechat_printf(
                workspace->buffer,
                _("%s%s: got response: %s"),
                weechat_prefix("network"), SLACK_PLUGIN_NAME,
                json_string);
            
            response = json_tokener_parse(json_string);
            ok = json_object_object_get(response, "ok");
            if (!json_valid(ok, workspace))
            {
                json_object_put(response);
                free(json_string);
                return 0;
            }

            if(json_object_get_boolean(ok))
            {
                self = json_object_object_get(response, "self");
                if (!json_valid(self, workspace))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }
                else
                {
                    id = json_object_object_get(self, "id");
                    if (!json_valid(id, workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }
                    workspace->user = strdup(json_object_get_string(id));

                    name = json_object_object_get(self, "name");
                    if (!json_valid(name, workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }
                    workspace->nick = strdup(json_object_get_string(name));
                }

                team = json_object_object_get(response, "team");
                if (!json_valid(team, workspace))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }
                else
                {
                    domain = json_object_object_get(team, "domain");
                    if (!json_valid(domain, workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }

                    id = json_object_object_get(team, "id");
                    if (!json_valid(id, workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }
                    workspace->id = strdup(json_object_get_string(id));

                    name = json_object_object_get(team, "name");
                    if (!json_valid(name, workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }
                    workspace->name = strdup(json_object_get_string(name));
                }

                url = json_object_object_get(response, "url");
                if (!json_valid(url, workspace))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }
                workspace->ws_url = strdup(json_object_get_string(url));
            }
            else
            {
                error = json_object_object_get(response, "error");
                if (!json_valid(error, workspace))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                weechat_printf(
                    workspace->buffer,
                    _("%s%s: failed to request websocket: %s"),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME,
                    json_object_get_string(error));
            }

            json_object_put(response);
            free(json_string);
        }
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        workspace->client_wsi = NULL;
        /* Does not doing this cause a leak?
        lws_cancel_service(lws_get_context(wsi));*/ /* abort poll wait */
        break;

    default:
        break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
    {
        "http",
        callback_http,
        0,
        0,
    },
    { NULL, NULL, 0, 0 }
};

struct t_slack_workspace *slack_workspace_search(const char *workspace_domain)
{
    struct t_slack_workspace *ptr_workspace;

    if (!workspace_domain)
        return NULL;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        if (strcmp(ptr_workspace->domain, workspace_domain) == 0)
            return ptr_workspace;
    }

    /* workspace not found */
    return NULL;
}

struct t_slack_workspace *slack_workspace_casesearch (const char *workspace_domain)
{
    struct t_slack_workspace *ptr_workspace;

    if (!workspace_domain)
        return NULL;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        if (weechat_strcasecmp (ptr_workspace->domain, workspace_domain) == 0)
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

struct t_slack_workspace *slack_workspace_alloc(const char *domain)
{
    struct t_slack_workspace *new_workspace;
    int i, length;
    char *option_name;

    if (slack_workspace_casesearch(domain))
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

	/* set properties */
	new_workspace->id = NULL;
	new_workspace->name = NULL;

    /* set name */
    new_workspace->domain = strdup(domain);

    /* internal vars */
    new_workspace->reloading_from_config = 0;
    new_workspace->reloaded_from_config = 0;

    new_workspace->is_connected = 0;
    new_workspace->disconnected = 0;

    new_workspace->idx = 0;
    new_workspace->uri = NULL;
    new_workspace->ws_url = NULL;
    new_workspace->client_wsi = NULL;
    new_workspace->context = NULL;
    new_workspace->json_chunks = NULL;
    new_workspace->requests = NULL;
    new_workspace->last_request = NULL;

    new_workspace->user = NULL;
    new_workspace->nick = NULL;

    new_workspace->buffer = NULL;
    new_workspace->buffer_as_string = NULL;
    new_workspace->users = NULL;
    new_workspace->last_user = NULL;
    new_workspace->channels = NULL;
    new_workspace->last_channel = NULL;

    /* create options with null value */
    for (i = 0; i < SLACK_WORKSPACE_NUM_OPTIONS; i++)
    {
        length = strlen(new_workspace->domain) + 1 +
            strlen(slack_workspace_options[i][0]) +
            512 +  /* inherited option name(slack.workspace_default.xxx) */
            1;
        option_name = malloc(length);
        if (option_name)
        {
            snprintf(option_name, length, "%s.%s << slack.workspace_default.%s",
                     new_workspace->domain,
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

void slack_workspace_free_data(struct t_slack_workspace *workspace)
{
    int i;

    if (!workspace)
        return;

    /* free linked lists */
    /*
    for (i = 0; i < IRC_SERVER_NUM_OUTQUEUES_PRIO; i++)
    {
        slack_workspace_outqueue_free_all(workspace, i);
    }
    slack_redirect_free_all(workspace);
    slack_notify_free_all(workspace);
    */
    slack_channel_free_all(workspace);
    slack_user_free_all(workspace);

    /* free hashtables */
    /*
    weechat_hashtable_free(workspace->join_manual);
    weechat_hashtable_free(workspace->join_channel_key);
    weechat_hashtable_free(workspace->join_noswitch);
    */

    /* free workspace data */
    for (i = 0; i < SLACK_WORKSPACE_NUM_OPTIONS; i++)
    {
        if (workspace->options[i])
            weechat_config_option_free(workspace->options[i]);
    }
    if (workspace->id)
        free(workspace->id);
    if (workspace->name)
        free(workspace->name);
    if (workspace->domain)
        free(workspace->domain);

    if (workspace->uri)
        free(workspace->uri);
    if (workspace->ws_url)
        free(workspace->ws_url);
    if (workspace->context)
        lws_context_destroy(workspace->context);
    while (workspace->json_chunks)
    {
        struct t_json_chunk *chunk_ptr = workspace->json_chunks->next;

        free(workspace->json_chunks->data);
        free(workspace->json_chunks);
        workspace->json_chunks = chunk_ptr;
    }
    while (workspace->requests)
    {
        struct t_slack_request *request_ptr = workspace->requests->next_request;

        workspace->requests->client_wsi = NULL;
        if (workspace->requests->context)
        {
            lws_context_destroy(workspace->requests->context);
            workspace->requests->context = NULL;
            if (workspace->requests->uri)
            {
                free(workspace->requests->uri);
                workspace->requests->uri = NULL;
            }
        }
        free(workspace->requests);
        workspace->requests = request_ptr;
    }

    if (workspace->user)
        free(workspace->user);
    if (workspace->nick)
        free(workspace->nick);

    if (workspace->buffer_as_string)
        free(workspace->buffer_as_string);

    slack_channel_free_all(workspace);
    slack_user_free_all(workspace);
}

void slack_workspace_free(struct t_slack_workspace *workspace)
{
    struct t_slack_workspace *new_slack_workspaces;

    if (!workspace)
        return;

    /*
     * close workspace buffer (and all channels/privates)
     * (only if we are not in a /upgrade, because during upgrade we want to
     * keep connections and closing workspace buffer would disconnect from workspace)
     */
    if (workspace->buffer)
        weechat_buffer_close(workspace->buffer);

    /* remove workspace from queue */
    if (last_slack_workspace == workspace)
        last_slack_workspace = workspace->prev_workspace;
    if (workspace->prev_workspace)
    {
        (workspace->prev_workspace)->next_workspace = workspace->next_workspace;
        new_slack_workspaces = slack_workspaces;
    }
    else
        new_slack_workspaces = workspace->next_workspace;

    if (workspace->next_workspace)
        (workspace->next_workspace)->prev_workspace = workspace->prev_workspace;

    slack_workspace_free_data(workspace);
    free(workspace);
    slack_workspaces = new_slack_workspaces;
}

void slack_workspace_free_all()
{
    /* for each workspace in memory, remove it */
    while (slack_workspaces)
    {
        slack_workspace_free(slack_workspaces);
    }
}

void slack_workspace_disconnect(struct t_slack_workspace *workspace,
								int reconnect)
{
	(void) reconnect;

    struct t_slack_channel *ptr_channel;
	(void) ptr_channel;

    if (workspace->is_connected)
    {
        /*
         * remove all nicks and write disconnection message on each
         * channel/private buffer
         */
        slack_user_free_all(workspace);
        weechat_nicklist_remove_all(workspace->buffer);
        for (ptr_channel = workspace->channels; ptr_channel;
             ptr_channel = ptr_channel->next_channel)
        {
            weechat_nicklist_remove_all(ptr_channel->buffer);
            weechat_printf(
                ptr_channel->buffer,
                _("%s%s: disconnected from workspace"),
                weechat_prefix("network"), SLACK_PLUGIN_NAME);
        }
        /* remove away status on workspace buffer */
        //weechat_buffer_set(workspace->buffer, "localvar_del_away", "");
    }

    slack_workspace_close_connection(workspace);

    if (workspace->buffer)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: disconnected from workspace"),
            weechat_prefix ("network"), SLACK_PLUGIN_NAME);
    }

    /*
    workspace->current_retry = 0;

    if (switch_address)
        slack_workspace_switch_address(workspace, 0);
    else
        slack_workspace_set_index_current_address(workspace, 0);

    if (workspace->nick_modes)
    {
        free (workspace->nick_modes);
        workspace->nick_modes = NULL;
        weechat_bar_item_update ("input_prompt");
        weechat_bar_item_update ("slack_nick_modes");
    }
    workspace->cap_away_notify = 0;
    workspace->cap_account_notify = 0;
    workspace->cap_extended_join = 0;
    workspace->is_away = 0;
    workspace->away_time = 0;
    workspace->lag = 0;
    workspace->lag_displayed = -1;
    workspace->lag_check_time.tv_sec = 0;
    workspace->lag_check_time.tv_usec = 0;
    workspace->lag_next_check = time (NULL) +
        weechat_config_integer (slack_config_network_lag_check);
    workspace->lag_last_refresh = 0;
    slack_workspace_set_lag (workspace);
    workspace->monitor = 0;
    workspace->monitor_time = 0;

    if (reconnect
        && IRC_SERVER_OPTION_BOOLEAN(workspace, IRC_SERVER_OPTION_AUTORECONNECT))
        slack_workspace_reconnect_schedule(workspace);
    else
    {
        workspace->reconnect_delay = 0;
        workspace->reconnect_start = 0;
    }
	*/

    /* discard current nick if no reconnection asked */
	/*
    if (!reconnect && workspace->nick)
        slack_workspace_set_nick(workspace, NULL);

    slack_workspace_set_buffer_title(workspace);

    workspace->disconnected = 1;
	*/

    /* send signal "slack_workspace_disconnected" with workspace name */
	/*
    (void) weechat_hook_signal_send("slack_workspace_disconnected",
                                    WEECHAT_HOOK_SIGNAL_STRING, workspace->name);
	*/
}

void slack_workspace_disconnect_all()
{
    struct t_slack_workspace *ptr_workspace;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        slack_workspace_disconnect(ptr_workspace, 0);
    }
}

struct t_gui_buffer *slack_workspace_create_buffer(struct t_slack_workspace *workspace)
{
    char buffer_name[256], charset_modifier[256];

    snprintf(buffer_name, sizeof(buffer_name),
             "workspace.%s", workspace->domain);
    workspace->buffer = weechat_buffer_new(buffer_name,
                                           &slack_input_data_cb, NULL, NULL,
                                           &slack_buffer_close_cb, NULL, NULL);
    if (!workspace->buffer)
        return NULL;

    if (!weechat_buffer_get_integer(workspace->buffer, "short_name_is_set"))
        weechat_buffer_set(workspace->buffer, "short_name", workspace->domain);
    weechat_buffer_set(workspace->buffer, "localvar_set_type", "server");
    weechat_buffer_set(workspace->buffer, "localvar_set_server", workspace->domain);
    weechat_buffer_set(workspace->buffer, "localvar_set_channel", workspace->domain);
    snprintf(charset_modifier, sizeof (charset_modifier),
             "workspace.%s", workspace->domain);
    weechat_buffer_set(workspace->buffer, "localvar_set_charset_modifier",
                       charset_modifier);
    weechat_buffer_set(workspace->buffer, "title",
                       (workspace->name) ? workspace->name : "");

    weechat_buffer_set(workspace->buffer, "nicklist", "1");
    weechat_buffer_set(workspace->buffer, "nicklist_display_groups", "0");
    weechat_buffer_set_pointer(workspace->buffer, "nicklist_callback",
                               &slack_buffer_nickcmp_cb);
    weechat_buffer_set_pointer(workspace->buffer, "nicklist_callback_pointer",
                               workspace);

    return workspace->buffer;
}

void slack_workspace_close_connection(struct t_slack_workspace *workspace)
{
    struct t_slack_request *ptr_request;

    workspace->is_connected = 0;
    workspace->client_wsi = NULL;
    workspace->context = NULL;

    for (ptr_request = workspace->requests; ptr_request;
         ptr_request = ptr_request->next_request)
    {
        if (ptr_request->context)
        {
            struct t_slack_request *new_requests;

            lws_context_destroy(ptr_request->context);
            ptr_request->context = NULL;
            if (ptr_request->uri)
            {
                free(ptr_request->uri);
                ptr_request->uri = NULL;
            }

            /* remove request from requests list */
            if (workspace->last_request == ptr_request)
                workspace->last_request = ptr_request->prev_request;
            if (ptr_request->prev_request)
            {
                (ptr_request->prev_request)->next_request = ptr_request->next_request;
                new_requests = workspace->requests;
            }
            else
                new_requests = ptr_request->next_request;

            if (ptr_request->next_request)
                (ptr_request->next_request)->prev_request = ptr_request->prev_request;

            workspace->requests = new_requests;
        }
    }
}

void slack_workspace_websocket_create(struct t_slack_workspace *workspace)
{
    struct lws_context_creation_info info;
    struct lws_client_connect_info i;
    const char *token;
    
    if (workspace->client_wsi)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error: a websocket already exists"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return;
    }

    token = weechat_config_string(workspace->options[SLACK_WORKSPACE_OPTION_TOKEN]);

    size_t urilen = snprintf(NULL, 0, endpoint, token) + 1;
    workspace->uri = malloc(urilen);
    snprintf(workspace->uri, urilen, endpoint, token);

    memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
    info.protocols = protocols;

    workspace->context = lws_create_context(&info);
    if (!workspace->context)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error connecting to slack: lws init failed"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return;
    }
    else
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: contacting slack.com:443"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME);
    }

    memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
    i.context = workspace->context;
    i.ssl_connection = LCCSCF_USE_SSL;
    i.port = 443;
    i.address = "slack.com";
    i.path = workspace->uri;
    i.host = i.address;
    i.origin = i.address;
    i.method = "GET";
    i.protocol = protocols[0].name;
    i.pwsi = &workspace->client_wsi;
    i.userdata = workspace;

    lws_client_connect_via_info(&i);

    workspace->is_connected = 1;
}

int slack_workspace_connect(struct t_slack_workspace *workspace)
{
	workspace->disconnected = 0;

	if (!workspace->buffer)
	{
        if (!slack_workspace_create_buffer(workspace))
            return 0;
        weechat_buffer_set(workspace->buffer, "display", "auto");
	}

    slack_workspace_close_connection(workspace);
    
    slack_workspace_websocket_create(workspace);
    
    return 1;
}

int slack_workspace_timer_cb(const void *pointer, void *data, int remaining_calls)
{
    struct t_slack_workspace *ptr_workspace;
    struct t_slack_request *ptr_request;

    /* make C compiler happy */
    (void) pointer;
    (void) data;
    (void) remaining_calls;

    for (ptr_workspace = slack_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        if (!ptr_workspace->is_connected)
            continue;

        for (ptr_request = ptr_workspace->requests; ptr_request;
             ptr_request = ptr_request->next_request)
        {
            if (ptr_request->client_wsi)
            {
                lws_service(ptr_request->context, 0);
            }
            else if (ptr_request->context)
            {
                struct t_slack_request *new_requests;

                lws_context_destroy(ptr_request->context);
                ptr_request->context = NULL;
                if (ptr_request->uri)
                {
                    free(ptr_request->uri);
                    ptr_request->uri = NULL;
                }

                /* remove request from requests list */
                if (ptr_workspace->last_request == ptr_request)
                    ptr_workspace->last_request = ptr_request->prev_request;
                if (ptr_request->prev_request)
                {
                    (ptr_request->prev_request)->next_request = ptr_request->next_request;
                    new_requests = ptr_workspace->requests;
                }
                else
                    new_requests = ptr_request->next_request;

                if (ptr_request->next_request)
                    (ptr_request->next_request)->prev_request = ptr_request->prev_request;

                ptr_workspace->requests = new_requests;
            }
        }

        if (ptr_workspace->client_wsi)
        {
            lws_service(ptr_workspace->context, 0);
        }
        else if (ptr_workspace->context)
        {
            lws_context_destroy(ptr_workspace->context);
            ptr_workspace->context = NULL;
            if (ptr_workspace->uri)
            {
                free(ptr_workspace->uri);
                ptr_workspace->uri = NULL;
            }
            if (ptr_workspace->ws_url)
            {
                slack_api_connect(ptr_workspace);
                free(ptr_workspace->ws_url);
                ptr_workspace->ws_url = NULL;
            }
        }
    }

    return WEECHAT_RC_OK;
}

void slack_workspace_register_request(struct t_slack_workspace *workspace,
                                      struct t_slack_request *request)
{
    request->prev_request = workspace->last_request;
    request->next_request = NULL;
    if (workspace->last_request)
        (workspace->last_request)->next_request = request;
    else
        workspace->requests = request;
    workspace->last_request = request;
}
