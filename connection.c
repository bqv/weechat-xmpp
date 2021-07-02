// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "config.h"
#include "account.h"
#include "user.h"
#include "channel.h"
#include "connection.h"

void connection__init()
{
    xmpp_initialize();
}

int version_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    const char *ns;
    struct t_account *account = (struct t_account *)userdata;
    const char *weechat_name = "weechat";
    const char *weechat_version = weechat_info_get("version", NULL);

    weechat_printf(NULL, "Received version request from %s", xmpp_stanza_get_from(stanza));

    reply = xmpp_stanza_reply(stanza);
    xmpp_stanza_set_type(reply, "result");

    query = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(query, "query");
    ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
    if (ns) {
        xmpp_stanza_set_ns(query, ns);
    }

    name = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(name, "name");
    xmpp_stanza_add_child(query, name);
    xmpp_stanza_release(name);

    text = xmpp_stanza_new(account->context);
    xmpp_stanza_set_text(text, weechat_name);
    xmpp_stanza_add_child(name, text);
    xmpp_stanza_release(text);

    version = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(version, "version");
    xmpp_stanza_add_child(query, weechat_version);
    xmpp_stanza_release(version);

    text = xmpp_stanza_new(account->context);
    xmpp_stanza_set_text(text, version);
    xmpp_stanza_add_child(version, text);
    xmpp_stanza_release(text);

    xmpp_stanza_add_child(reply, query);
    xmpp_stanza_release(query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    if (version)
        free (version);

    return 1;
}

int message_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    struct t_account *account = (struct t_account *)userdata;
    xmpp_stanza_t *body, *reply, *to;
    const char *type, *from, *from_bare;
    char *intext, *replytext;

    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL)
        return 1;
    type = xmpp_stanza_get_type(stanza);
    if (type != NULL && strcmp(type, "error") == 0)
        return 1;
    from = xmpp_stanza_get_from(stanza);
    if (from == NULL)
        return 1;
    from_bare = xmpp_jid_bare(account->context, from);
    to = xmpp_stanza_get_to(stanza);

    intext = xmpp_stanza_get_text(body);
    if (intext == NULL)
        intext = strdup("");

    struct t_channel *channel = channel__search(account, from_bare);
    if (!channel)
        channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);

    if (weechat_strcasecmp(type, "groupchat") == 0)
    {
        from = weechat_strcasecmp(channel->name,
                                  xmpp_jid_bare(account->context,
                                                from)) == 0
            ? xmpp_jid_resource(account->context, from)
            : from;
    }

    if (strcmp(to, channel->id) == 0)
        weechat_printf(channel->buffer, "%s[to %s]: %s",
                       user__as_prefix_raw(account->context, from),
                       to, intext);
    else if (weechat_string_match(intext, "/me *", 0))
        weechat_printf(channel->buffer, "%s%s %s",
                       weechat_prefix("action"), from, intext+4);
    else
        weechat_printf(channel->buffer, "%s%s",
                       user__as_prefix_raw(account->context, from),
                       intext);

    xmpp_free(account->context, intext);

    return 1;
}

void connection__handler(xmpp_conn_t *conn, xmpp_conn_event_t status,
                         int error, xmpp_stream_error_t *stream_error,
                         void *userdata)
{
    struct t_account *account = (struct t_account *)userdata;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT) {
        xmpp_stanza_t *pres;
      //weechat_printf(account->buffer, "DEBUG: connected");
        xmpp_handler_add(conn, version_handler, "jabber:iq:version", "iq", NULL,
                         account);
        xmpp_handler_add(conn, message_handler, NULL, "message", NULL, account);

        /* Send initial <presence/> so that we appear online to contacts */
        pres = xmpp_presence_new(account->context);
        xmpp_stanza_set_from(pres, account_jid(account));
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);
    } else {
      //weechat_printf(account->buffer, "DEBUG: disconnected");
      //xmpp_stop(account->context);
    }
}

char *const rand_string(int length)
{
    char *string = malloc(length);
    srand(time(NULL));
    for(int i = 0; i < length; ++i){
        string[i] = '0' + rand()%72; // starting on '0', ending on '}'
        if (!((string[i] >= '0' && string[i] <= '9') ||
              (string[i] >= 'A' && string[i] <= 'Z') ||
              (string[i] >= 'a' && string[i] <= 'z')))
            i--; // reroll
    }
    string[length] = 0;
    return string;
}

int connection__connect(struct t_account *account, xmpp_conn_t **connection,
                        const char* jid, const char* password, int tls)
{
    *connection = xmpp_conn_new(account->context);
    char *resource = account_resource(account);
    if (!(resource && strlen(resource)))
    {
        char *const rand = rand_string(8);
        char ident[64] = {0};
        snprintf(ident, sizeof(ident), "weechat.%s", rand);
        free(rand);

        account_option_set(account, ACCOUNT_OPTION_RESOURCE, ident);
        resource = account_resource(account);
    }
    xmpp_conn_set_jid(*connection,
                      xmpp_jid_new(account->context,
                                   xmpp_jid_node(account->context, jid),
                                   xmpp_jid_domain(account->context, jid),
                                   resource));
    xmpp_conn_set_pass(*connection, password);

    auto flags = xmpp_conn_get_flags(*connection);
    switch (tls)
    {
        case 0:
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
            break;
        case 1:
            flags |= ~XMPP_CONN_FLAG_DISABLE_TLS;
            flags |= ~XMPP_CONN_FLAG_TRUST_TLS;
            break;
        case 2:
            flags |= XMPP_CONN_FLAG_TRUST_TLS;
            break;
        default:
            break;
    }
    xmpp_conn_set_flags(*connection, flags);

    if (xmpp_connect_client(*connection, NULL, 0, &connection__handler, account)
        != XMPP_EOK)
    {
        weechat_printf(
            NULL,
            _("%s%s: error connecting to %s"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            jid);
        return 0;
    }

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
