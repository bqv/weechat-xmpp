// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "config.h"
#include "connection.h"
//#include "api/xmpp-api-hello.h"
//#include "api/xmpp-api-error.h"
//#include "api/xmpp-api-message.h"
//#include "api/xmpp-api-user-typing.h"

xmpp_conn_t *connection;

void connection__init()
{
    xmpp_initialize();
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

void connection__handler(xmpp_conn_t *conn, xmpp_conn_event_t status,
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

int connection__connect(xmpp_ctx_t *context, xmpp_conn_t **connection,
                        xmpp_log_t *logger, const char* jid,
                        const char* password, int tls)
{
    *connection = xmpp_conn_new(context);
    xmpp_conn_set_jid(*connection, jid);
    xmpp_conn_set_pass(*connection, password);

    auto flags = xmpp_conn_get_flags(*connection);
    switch (tls)
    {
        case 0:
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
            break;
        case 1:
            break;
        case 2:
            flags |= XMPP_CONN_FLAG_TRUST_TLS;
            break;
        default:
            break;
    }
    xmpp_conn_set_flags(*connection, flags);

    if (xmpp_connect_client(*connection, NULL, 0, &connection__handler, context)
        != XMPP_EOK)
    {
        weechat_printf(
            NULL,
            _("%s%s: error connecting to %s"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            jid);
        return 0;
    }

        weechat_printf(
            NULL,
            _("%s%s: c'necting to %s"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            jid);
    return 1;
}

void connection__process(xmpp_ctx_t *context, xmpp_conn_t *connection,
                         const unsigned long timeout)
{
    if (connection)
    {
        xmpp_run_once(context ? context : xmpp_conn_get_context(connection),
                      timeout);
    }
}

int connection__route_message(xmpp_conn_t *workspace,
                                  const char *type, void *message)
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
