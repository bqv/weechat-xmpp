#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <json.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-oauth.h"

static void (*weechat_callback)(char *token);

static const char *const endpoint = "/api/oauth.access?"
    "client_id=%s&client_secret=%s&code=%s";
static char *uri;

static int n = 0;
static struct lws *client_wsi = NULL;
static struct lws_context *context = NULL;

static struct t_hook *slack_oauth_hook_timer = NULL;

static inline int json_valid(json_object *object)
{
    if (!object)
    {
        weechat_printf(
            NULL,
            _("%s%s: error retrieving token: unexpected response from server"),
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
            _("%s%s: retrieving token... (%d)"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME,
            status);
        break;

    /* chunks of chunked content, with header removed */
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
        {
            char *json_string = weechat_strndup(in, (int)len);
            json_object *response, *ok, *error, *token;

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
                token = json_object_object_get(response, "access_token");
                if (!json_valid(token))
                {
                    json_object_put(response);
                    free(json_string);
                    return 0;
                }

                weechat_printf(
                    NULL,
                    _("%s%s: retrieved token: %s"),
                    weechat_prefix("network"), SLACK_PLUGIN_NAME,
                    json_object_get_string(token));

                weechat_callback(strdup(json_object_get_string(token)));
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
                    _("%s%s: failed to retrieve token: %s"),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME,
                    json_object_get_string(error));
            }

            json_object_put(response);
            free(json_string);
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
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        client_wsi = NULL;
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

int slack_oauth_timer_cb(const void *pointer, void *data, int remaining_calls)
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

        if (slack_oauth_hook_timer)
            weechat_unhook(slack_oauth_hook_timer);
    }

    return WEECHAT_RC_OK;
}

void slack_oauth_request_token(char *code, void (*callback)(char *token))
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

    size_t urilen = snprintf(NULL, 0, endpoint, SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, code) + 1;
    uri = malloc(urilen);
    snprintf(uri, urilen, endpoint, SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, code);

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

    slack_oauth_hook_timer = weechat_hook_timer(1 * 1000, 0, 0,
                                                &slack_oauth_timer_cb,
                                                NULL, NULL);

    weechat_callback = callback;
}
