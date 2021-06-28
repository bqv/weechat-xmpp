// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <json.h>
#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "xmpp.h"
#include "xmpp-config.h"
#include "xmpp-connection.h"
//#include "api/xmpp-api-hello.h"
//#include "api/xmpp-api-error.h"
//#include "api/xmpp-api-message.h"
//#include "api/xmpp-api-user-typing.h"

xmpp_conn_t *xmpp_connection;

void xmpp_log_emit_weechat(void *const userdata, const xmpp_log_level_t level, const char *const area, const char *const msg)
{
    (void) userdata;

    static const char *log_level_name[4] = {"debug", "info", "warn", "error"};

    time_t date = time(NULL);
    const char *timestamp = weechat_util_get_time_string(&date);

    weechat_printf(
        NULL,
        _("%s%s/%s (%s): %s"),
        weechat_prefix("error"), XMPP_PLUGIN_NAME, area,
        log_level_name[level], msg);
}

xmpp_log_t xmpp_logger = {
    &xmpp_log_emit_weechat,
    NULL
};

void xmpp_connection_init()
{
    xmpp_initialize();
}

int xmpp_connection_autoconnect(const void *pointer, void *data, int remaining_calls)
{
    xmpp_connection_connect(weechat_config_string(xmpp_config_server_jid),
                            weechat_config_string(xmpp_config_server_password));

    return WEECHAT_RC_OK;
}

int version_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    const char *ns;
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    weechat_printf(NULL, "Received version request from %s", xmpp_stanza_get_from(stanza));

    reply = xmpp_stanza_reply(stanza);
    xmpp_stanza_set_type(reply, "result");

    query = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(query, "query");
    ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
    if (ns) {
        xmpp_stanza_set_ns(query, ns);
    }

    name = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(name, "name");
    xmpp_stanza_add_child(query, name);
    xmpp_stanza_release(name);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "libstrophe example bot");
    xmpp_stanza_add_child(name, text);
    xmpp_stanza_release(text);

    version = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(version, "version");
    xmpp_stanza_add_child(query, version);
    xmpp_stanza_release(version);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "1.0");
    xmpp_stanza_add_child(version, text);
    xmpp_stanza_release(text);

    xmpp_stanza_add_child(reply, query);
    xmpp_stanza_release(query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    return 1;
}

int message_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    xmpp_stanza_t *body, *reply;
    const char *type;
    char *intext, *replytext;
    int quit = 0;

    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL)
        return 1;
    type = xmpp_stanza_get_type(stanza);
    if (type != NULL && strcmp(type, "error") == 0)
        return 1;

    intext = xmpp_stanza_get_text(body);

    weechat_printf(NULL, "Incoming message from %s: %s", xmpp_stanza_get_from(stanza),
           intext);

    reply = xmpp_stanza_reply(stanza);
    if (xmpp_stanza_get_type(reply) == NULL)
        xmpp_stanza_set_type(reply, "chat");

    if (strcmp(intext, "quit") == 0) {
        replytext = strdup("bye!");
        quit = 1;
    } else {
        replytext = (char *)malloc(strlen(" to you too!") + strlen(intext) + 1);
        strcpy(replytext, intext);
        strcat(replytext, " to you too!");
    }
    xmpp_free(ctx, intext);
    xmpp_message_set_body(reply, replytext);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    free(replytext);

    if (quit)
        xmpp_disconnect(conn);

    return 1;
}

void xmpp_connection_on_connected(xmpp_conn_t *conn, xmpp_conn_event_t status,
                                  int error, xmpp_stream_error_t *stream_error,
                                  void *userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT) {
        xmpp_stanza_t *pres;
        weechat_printf(NULL, "DEBUG: connected");
        xmpp_handler_add(conn, version_handler, "jabber:iq:version", "iq", NULL,
                         ctx);
        xmpp_handler_add(conn, message_handler, NULL, "message", NULL, ctx);

        /* Send initial <presence/> so that we appear online to contacts */
        pres = xmpp_presence_new(ctx);
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);
    } else {
        weechat_printf(NULL, "DEBUG: disconnected");
        xmpp_stop(ctx);
    }
}

void xmpp_connection_connect(const char* jid, const char* password)
{
    xmpp_ctx_t *xmpp_context = xmpp_ctx_new(NULL, &xmpp_logger);

    xmpp_connection = xmpp_conn_new(xmpp_context);
    xmpp_conn_set_jid(xmpp_connection, jid);
    xmpp_conn_set_pass(xmpp_connection, password);
    auto flags = xmpp_conn_get_flags(xmpp_connection);
  //flags |= XMPP_CONN_FLAG_TRUST_TLS;
    xmpp_conn_set_flags(xmpp_connection, flags);
    xmpp_connect_client(xmpp_connection, NULL, 0, xmpp_connection_on_connected, xmpp_context);
  //struct lws_context_creation_info ctxinfo;
  //struct lws_client_connect_info ccinfo;
  //const char *url_protocol, *url_path;
  //char path[512];

  //memset(&ctxinfo, 0, sizeof(ctxinfo));
  //memset(&ccinfo, 0, sizeof(ccinfo));

  //ccinfo.port = 443;

  //if (lws_parse_uri(workspace->ws_url,
  //                  &url_protocol, &ccinfo.address,
  //                  &ccinfo.port, &url_path))
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: error connecting to xmpp: bad websocket uri"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME);
  //    return;
  //}

  //path[0] = '/';
  //strncpy(path + 1, url_path, sizeof(path) - 2);
  //path[sizeof(path) - 1] = '\0';

  //ccinfo.path = path;

  //ctxinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  //ctxinfo.port = CONTEXT_PORT_NO_LISTEN;
  //ctxinfo.protocols = protocols;
  //ctxinfo.uid = -1;
  //ctxinfo.gid = -1;

  //workspace->context = lws_create_context(&ctxinfo);
  //if (!workspace->context)
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: error connecting to xmpp: lws init failed"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME);
  //    return;
  //}
  //else
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: connecting to %s://%s:%d%s"),
  //        weechat_prefix("network"), XMPP_PLUGIN_NAME,
  //        url_protocol, ccinfo.address, ccinfo.port, path);
  //}

  //ccinfo.context = workspace->context;
  //ccinfo.ssl_connection = LCCSCF_USE_SSL;
  //ccinfo.host = ccinfo.address;
  //ccinfo.origin = ccinfo.address;
  //ccinfo.ietf_version_or_minus_one = -1;
  //ccinfo.protocol = protocols[0].name;
  //ccinfo.pwsi = &workspace->client_wsi;
  //ccinfo.userdata = workspace;

  //lws_client_connect_via_info(&ccinfo);
}

int xmpp_connection_check_events(const void *pointer, void *data, int remaining_calls)
{
    (void) pointer;
    (void) data;
    (void) remaining_calls;

    if (xmpp_connection)
    {
        xmpp_ctx_t *xmpp_context = xmpp_conn_get_context(xmpp_connection);

        xmpp_run_once(xmpp_context, 10);
    }

    return WEECHAT_RC_OK;
}

int xmpp_connection_route_message(xmpp_conn_t *workspace,
                                  const char *type, json_object *message)
{
  //struct stringcase key;
  //key.string = type;

  //size_t case_count = sizeof(cases) / sizeof(cases[0]);
  //void *entry_ptr = bsearch(&key, cases, case_count,
  //        sizeof(struct stringcase), stringcase_cmp);

  //if (entry_ptr)
  //{
  //    struct stringcase *entry = (struct stringcase *)entry_ptr;
  //    return (*entry->func)(workspace, message);
  //}
  //else
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: got unhandled message of type: %s"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME,
  //        type);
        return 1;
  //}
}
