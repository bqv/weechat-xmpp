// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <json.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-teaminfo.h"

static void (*weechat_callback)(struct t_slack_teaminfo *slack_teaminfo);

static const char *const endpoint = "/api/team.info?"
    "token=%s";
static char *uri;

static int n = 0;
static struct lws *client_wsi = NULL;
static struct lws_context *context = NULL;

static struct t_hook *slack_teaminfo_hook_timer = NULL;

struct t_json_chunk
{
    char *data;
    struct t_json_chunk *next;
};

static struct t_json_chunk *slack_teaminfo_chunks = NULL;
static struct t_slack_teaminfo slack_teaminfo;

static inline int json_valid(json_object *object)
{
    if (!object)
    {
        weechat_printf(
            NULL,
            _("%s%s: error retrieving workspace info: unexpected response from server"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return 0;
    }

    return 1;
}

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len)
{
    int status;

    switch (reason)
    {
    /* because we are protocols[0] ... */
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        weechat_printf(
            NULL,
            _("%s%s: error connecting to slack: %s"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            in ? (char *)in : "(null)");
        client_wsi = NULL;
        break;

    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        status = lws_http_client_http_response(wsi);
        weechat_printf(
            NULL,
            _("%s%s: retrieving workspace details... (%d)"),
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

            if (slack_teaminfo_chunks)
            {
                for (last_chunk = slack_teaminfo_chunks; last_chunk->next;
                        last_chunk = last_chunk->next);
                last_chunk->next = new_chunk;
            }
            else
            {
                slack_teaminfo_chunks = new_chunk;
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
            json_object *response, *ok, *error, *team;
            json_object *id, *name, *domain, *email_domain;
            struct t_json_chunk *chunk_ptr;

            chunk_count = 0;
            if (slack_teaminfo_chunks)
            {
                chunk_count++;
                for (chunk_ptr = slack_teaminfo_chunks; chunk_ptr->next;
                        chunk_ptr = chunk_ptr->next)
                {
                    chunk_count++;
                }
            }

            json_string = malloc((1024 * sizeof(char) * chunk_count) + 1);
            json_string[0] = '\0';

            chunk_ptr = slack_teaminfo_chunks;
            for (i = 0; i < chunk_count; i++)
            {
                strncat(json_string, chunk_ptr->data, 1024);
                chunk_ptr = chunk_ptr->next;

                free(slack_teaminfo_chunks->data);
                free(slack_teaminfo_chunks);
                slack_teaminfo_chunks = chunk_ptr;
            }

            weechat_printf(
                NULL,
                _("%s%s: got response: %s"),
                weechat_prefix("network"), SLACK_PLUGIN_NAME,
                json_string);
            
            response = json_tokener_parse(json_string);
            ok = json_object_object_get(response, "ok");
            if (!json_valid(ok))
            {
                json_object_put(response);
                free(json_string);
                return 0;
            }

            if(json_object_get_boolean(ok))
            {
                team = json_object_object_get(response, "team");
                if (!json_valid(team))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                id = json_object_object_get(team, "id");
                if (!json_valid(id))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                name = json_object_object_get(team, "name");
                if (!json_valid(name))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                domain = json_object_object_get(team, "domain");
                if (!json_valid(domain))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                email_domain = json_object_object_get(team, "email_domain");
                if (!json_valid(email_domain))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                weechat_printf(
                    NULL,
                    _("%s%s: retrieved workspace details for %s@%s"),
                    weechat_prefix("network"), SLACK_PLUGIN_NAME,
                    json_object_get_string(name), json_object_get_string(domain));

                slack_teaminfo.id = json_object_get_string(id);
                slack_teaminfo.name = json_object_get_string(name);
                slack_teaminfo.domain = json_object_get_string(domain);
                slack_teaminfo.email_domain = json_object_get_string(email_domain);

                weechat_callback(&slack_teaminfo);
            }
            else
            {
                error = json_object_object_get(response, "error");
                if (!json_valid(error))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                weechat_printf(
                    NULL,
                    _("%s%s: failed to retrieve workspace details: %s"),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME,
                    json_object_get_string(error));
            }

            json_object_put(response);
            free(json_string);
        }
        /* fallthrough */
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        client_wsi = NULL;
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

int slack_teaminfo_timer_cb(const void *pointer, void *data, int remaining_calls)
{
    (void) pointer;
    (void) data;
    (void) remaining_calls;

    if (n >= 0 && client_wsi)
    {
        n = lws_service(context, 0);
    }
    else if (context)
    {
        lws_context_destroy(context);
        context = NULL;
        free(uri);

        if (slack_teaminfo_hook_timer)
            weechat_unhook(slack_teaminfo_hook_timer);
    }

    return WEECHAT_RC_OK;
}

void slack_teaminfo_fetch(char *token, void (*callback)(struct t_slack_teaminfo *slack_teaminfo))
{
    struct lws_context_creation_info info;
    struct lws_client_connect_info i;

    if (client_wsi)
    {
        weechat_printf(
            NULL,
            _("%s%s: error: a registration is already in progress"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return;
    }

    slack_teaminfo.token = strdup(token);

    size_t urilen = snprintf(NULL, 0, endpoint, token) + 1;
    uri = malloc(urilen);
    snprintf(uri, urilen, endpoint, token);

    memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
    info.protocols = protocols;

    context = lws_create_context(&info);
    if (!context)
    {
        weechat_printf(
            NULL,
            _("%s%s: error connecting to slack: lws init failed"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return;
    }
    else
    {
        weechat_printf(
            NULL,
            _("%s%s: contacting slack.com:443"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME);
    }

    memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
    i.context = context;
    i.ssl_connection = LCCSCF_USE_SSL;
    i.port = 443;
    i.address = "slack.com";
    i.path = uri;
    i.host = i.address;
    i.origin = i.address;
    i.method = "GET";
    i.protocol = protocols[0].name;
    i.pwsi = &client_wsi;

    lws_client_connect_via_info(&i);

    slack_teaminfo_hook_timer = weechat_hook_timer(1 * 1000, 0, 0,
                                                   &slack_teaminfo_timer_cb,
                                                   NULL, NULL);

    weechat_callback = callback;
}

void free_teaminfo(struct t_slack_teaminfo *teaminfo)
{
    free(teaminfo->token);
}
