#include <libwebsockets.h>
#include <json.h>
#include <stdlib.h>
#include <string.h>

#include "../weechat-plugin.h"
#include "../slack.h"
#include "../slack-workspace.h"
#include "../slack-request.h"
#include "../slack-channel.h"
#include "../request/slack-request-channels-list.h"

static const char *const endpoint = "/api/channels.list?"
    "token=%s&cursor=%s&"
    "exclude_archived=false&exclude_members=true&limit=0";

static inline int json_valid(json_object *object, struct t_slack_workspace *workspace)
{
    if (!object)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error retrieving channels: unexpected response from server"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        __asm__("int3");
        return 0;
    }

    return 1;
}

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len)
{
    struct t_slack_request *request = (struct t_slack_request *)user;

    int status;

    switch (reason)
    {
    /* because we are protocols[0] ... */
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        weechat_printf(
            request->workspace->buffer,
            _("%s%s: error connecting to slack: %s"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            in ? (char *)in : "(null)");
        request->client_wsi = NULL;
        break;

    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        status = lws_http_client_http_response(wsi);
        weechat_printf(
            request->workspace->buffer,
            _("%s%s: retrieving channels... (%d)"),
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

            if (request->json_chunks)
            {
                for (last_chunk = request->json_chunks; last_chunk->next;
                        last_chunk = last_chunk->next);
                last_chunk->next = new_chunk;
            }
            else
            {
                request->json_chunks = new_chunk;
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
            json_object *response, *ok, *error, *channels;
            json_object *channel, *id, *name, *topic;
            struct t_json_chunk *chunk_ptr;

            chunk_count = 0;
            if (request->json_chunks)
            {
                chunk_count++;
                for (chunk_ptr = request->json_chunks; chunk_ptr->next;
                        chunk_ptr = chunk_ptr->next)
                {
                    chunk_count++;
                }
            }

            json_string = malloc((1024 * sizeof(char) * chunk_count) + 1);
            json_string[0] = '\0';

            chunk_ptr = request->json_chunks;
            for (i = 0; i < chunk_count; i++)
            {
                strncat(json_string, chunk_ptr->data, 1024);
                chunk_ptr = chunk_ptr->next;

                free(request->json_chunks->data);
                free(request->json_chunks);
                request->json_chunks = chunk_ptr;
            }

            weechat_printf(
                request->workspace->buffer,
                _("%s%s: got response: %s"),
                weechat_prefix("network"), SLACK_PLUGIN_NAME,
                json_string);
            
            response = json_tokener_parse(json_string);
            ok = json_object_object_get(response, "ok");
            if (!json_valid(ok, request->workspace))
            {
                json_object_put(response);
                free(json_string);
                return 0;
            }

            if(json_object_get_boolean(ok))
            {
                channels = json_object_object_get(response, "channels");
                if (!json_valid(channels, request->workspace))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                for (i = json_object_array_length(channels); i > 0; i--)
                {
                    struct t_slack_channel *new_channel;

                    channel = json_object_array_get_idx(channels, i - 1);
                    if (!json_valid(channel, request->workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }

                    id = json_object_object_get(channel, "id");
                    if (!json_valid(id, request->workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }

                    name = json_object_object_get(channel, "name");
                    if (!json_valid(name, request->workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }

                    topic = json_object_object_get(channel, "topic");
                    if (!json_valid(topic, request->workspace))
                    {
                        json_object_put(response);
                        free(json_string);
                        return 0;
                    }

                    new_channel = slack_channel_new(
                                    request->workspace,
                                    SLACK_CHANNEL_TYPE_CHANNEL,
                                    json_object_get_string(id),
                                    json_object_get_string(name));
                }
            }
            else
            {
                error = json_object_object_get(response, "error");
                if (!json_valid(error, request->workspace))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                weechat_printf(
                    request->workspace->buffer,
                    _("%s%s: failed to retrieve channels: %s"),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME,
                    json_object_get_string(error));
            }

            json_object_put(response);
            free(json_string);
        }
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        request->client_wsi = NULL;
        lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
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

struct t_slack_request *slack_request_channels_list(
                                   struct t_slack_workspace *workspace,
                                   const char *token, const char *cursor)
{
    struct t_slack_request *request;
    struct lws_context_creation_info ctxinfo;
    struct lws_client_connect_info ccinfo;

    request = slack_request_alloc(workspace);

    size_t urilen = snprintf(NULL, 0, endpoint, token, cursor) + 1;
    request->uri = malloc(urilen);
    snprintf(request->uri, urilen, endpoint, token, cursor);

    memset(&ctxinfo, 0, sizeof(ctxinfo)); /* otherwise uninitialized garbage */
    ctxinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    ctxinfo.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
    ctxinfo.protocols = protocols;

    request->context = lws_create_context(&ctxinfo);
    if (!request->context)
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error connecting to slack: lws init failed"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return NULL;
    }
    else
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: contacting slack.com:443"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME);
    }

    memset(&ccinfo, 0, sizeof(ccinfo)); /* otherwise uninitialized garbage */
    ccinfo.context = request->context;
    ccinfo.ssl_connection = LCCSCF_USE_SSL;
    ccinfo.port = 443;
    ccinfo.address = "slack.com";
    ccinfo.path = request->uri;
    ccinfo.host = ccinfo.address;
    ccinfo.origin = ccinfo.address;
    ccinfo.method = "GET";
    ccinfo.protocol = protocols[0].name;
    ccinfo.pwsi = &request->client_wsi;
    ccinfo.userdata = request;

    lws_client_connect_via_info(&ccinfo);

    return request;
}
