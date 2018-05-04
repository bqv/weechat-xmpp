#include <libwebsockets.h>
#include <json.h>
#include <stdlib.h>
#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-api.h"
#include "api/slack-api-hello.h"
#include "api/slack-api-error.h"
#include "api/slack-api-message.h"

struct stringcase
{
    const char *string;
    int (*func)(struct t_slack_workspace *workspace,
                json_object *message);
};

static struct stringcase cases[] =
{ { "hello", &slack_api_hello }
, { "error", &slack_api_error }
, { "message", &slack_api_message }
};

static int stringcase_cmp(const void *p1, const void *p2)
{
    return strcasecmp(((struct stringcase*)p1)->string, ((struct stringcase*)p2)->string);
}

void slack_api_init()
{
    size_t case_count = sizeof(cases) / sizeof(cases[0]);
    qsort(cases, case_count, sizeof(struct stringcase), stringcase_cmp);

    slack_api_message_init();
}

static int callback_ws(struct lws* wsi, enum lws_callback_reasons reason,
                       void *user, void* in, size_t len)
{
    struct t_slack_workspace *workspace = (struct t_slack_workspace *)user;

    (void) wsi;

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

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        weechat_printf(
            workspace->buffer,
            _("%s%s: waiting for hello..."),
            weechat_prefix("network"), SLACK_PLUGIN_NAME);
        break;

    /* data is never chunked */
    case LWS_CALLBACK_CLIENT_RECEIVE:
        weechat_printf(
            workspace->buffer,
            _("%s%s: received data: %s"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME,
            (const char *)in);
        {
            char *json_string;
            json_object *response, *type;

            json_string = strdup((const char *)in);

            response = json_tokener_parse(json_string);
            type = json_object_object_get(response, "type");
            if (!type)
            {
                weechat_printf(
                    workspace->buffer,
                    _("%s%s: unexpected data received from websocket: closing"),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME);

                slack_workspace_disconnect(workspace, 0);

                json_object_put(response);
                free(json_string);
                return -1;
            }

            if (!slack_api_route_message(workspace,
                    json_object_get_string(type), response))
            {
                weechat_printf(
                    workspace->buffer,
                    _("%s%s: error while handling message: %s"),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME,
                    json_string);
                weechat_printf(
                    workspace->buffer,
                    _("%s%s: closing connection."),
                    weechat_prefix("error"), SLACK_PLUGIN_NAME);

                slack_workspace_disconnect(workspace, 0);

                json_object_put(response);
                free(json_string);
                return -1;
            }

            json_object_put(response);
            free(json_string);
        }
        return 0; /* don't passthru */

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        weechat_printf(
            workspace->buffer,
            _("%s%s: websocket is writeable"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME);
        break;

    case LWS_CALLBACK_CLOSED:
        workspace->client_wsi = NULL;
        workspace->disconnected = 1;
        /* start reconnect timer */
        break;

    default:
        break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
    {
        "default",
        callback_ws,
        0,
        0,
    },
    { NULL, NULL, 0, 0 }
};

void slack_api_connect(struct t_slack_workspace *workspace)
{
    struct lws_context_creation_info ctxinfo;
    struct lws_client_connect_info ccinfo;
    const char *url_protocol, *url_path;
    char path[512];

    memset(&ctxinfo, 0, sizeof(ctxinfo));
    memset(&ccinfo, 0, sizeof(ccinfo));

    ccinfo.port = 443;

    if (lws_parse_uri(workspace->ws_url,
                      &url_protocol, &ccinfo.address,
                      &ccinfo.port, &url_path))
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: error connecting to slack: bad websocket uri"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME);
        return;
    }

    path[0] = '/';
    strncpy(path + 1, url_path, sizeof(path) - 2);
    path[sizeof(path) - 1] = '\0';

    ccinfo.path = path;

    ctxinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    ctxinfo.port = CONTEXT_PORT_NO_LISTEN;
    ctxinfo.protocols = protocols;
    ctxinfo.uid = -1;
    ctxinfo.gid = -1;

    workspace->context = lws_create_context(&ctxinfo);
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
            _("%s%s: connecting to %s://%s:%d%s"),
            weechat_prefix("network"), SLACK_PLUGIN_NAME,
            url_protocol, ccinfo.address, ccinfo.port, path);
    }

    ccinfo.context = workspace->context;
    ccinfo.ssl_connection = LCCSCF_USE_SSL;
    ccinfo.host = ccinfo.address;
    ccinfo.origin = ccinfo.address;
    ccinfo.ietf_version_or_minus_one = -1;
    ccinfo.protocol = protocols[0].name;
    ccinfo.pwsi = &workspace->client_wsi;
    ccinfo.userdata = workspace;

    lws_client_connect_via_info(&ccinfo);
}

int slack_api_route_message(struct t_slack_workspace *workspace,
                            const char *type, json_object *message)
{
    struct stringcase key;
    key.string = type;

    size_t case_count = sizeof(cases) / sizeof(cases[0]);
    void *entry_ptr = bsearch(&key, cases, case_count,
            sizeof(struct stringcase), stringcase_cmp);

    if (entry_ptr)
    {
        struct stringcase *entry = (struct stringcase *)entry_ptr;
        return (*entry->func)(workspace, message);
    }
    else
    {
        weechat_printf(
            workspace->buffer,
            _("%s%s: got unhandled message of type: %s"),
            weechat_prefix("error"), SLACK_PLUGIN_NAME,
            type);
        return 1;
    }
}
