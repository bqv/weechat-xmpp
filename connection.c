// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "xmpp/stanza.h"
#include "config.h"
#include "account.h"
#include "user.h"
#include "channel.h"
#include "connection.h"
#include "omemo.h"

void connection__init()
{
    xmpp_initialize();
}

int connection__version_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    const char *ns;
    struct t_account *account = (struct t_account *)userdata;
    const char *weechat_name = "weechat";
    char *weechat_version = weechat_info_get("version", NULL);

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
    xmpp_stanza_add_child(query, version);
    xmpp_stanza_release(version);

    text = xmpp_stanza_new(account->context);
    xmpp_stanza_set_text(text, weechat_version);
    xmpp_stanza_add_child(version, text);
    xmpp_stanza_release(text);

    xmpp_stanza_add_child(reply, query);
    xmpp_stanza_release(query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    if (weechat_version)
        free(weechat_version);

    return 1;
}

int connection__presence_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void) conn;

    struct t_account *account = (struct t_account *)userdata;
    struct t_user *user;
    struct t_channel *channel;
    xmpp_stanza_t *iq__x, *iq__x__item;
    const char *from, *from_bare, *role = NULL, *affiliation = NULL;

    from = xmpp_stanza_get_from(stanza);
    if (from == NULL)
        return 1;
    from_bare = xmpp_jid_bare(account->context, from);
    iq__x = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "x", "http://jabber.org/protocol/muc#user");
    if (iq__x)
    {
        iq__x__item = xmpp_stanza_get_child_by_name(iq__x, "item");
        role = xmpp_stanza_get_attribute(iq__x__item, "role");
        affiliation = xmpp_stanza_get_attribute(iq__x__item, "affiliation");
    }

    user = user__search(account, from);
    if (!user)
        user = user__new(account, from, from);

    channel = channel__search(account, from_bare);
    if (!iq__x)
    {
        if (!channel)
            channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);
        channel__add_member(account, channel, from);
    }
    else if (channel)
    {
        if (weechat_strcasecmp(role, "none") == 0)
            channel__remove_member(account, channel, from);
        channel__add_member(account, channel, from);
    }

    return 1;
}

int connection__message_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void) conn;

    struct t_account *account = (struct t_account *)userdata;
    struct t_channel *channel;
    xmpp_stanza_t *body, *delay, *topic;
    const char *type, *from, *from_bare, *to, *timestamp = 0;
    char *intext;
    struct tm time = {0};
    time_t date = 0;

    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL)
    {
        topic = xmpp_stanza_get_child_by_name(stanza, "subject");
        if (topic == NULL)
            return 1;
        intext = xmpp_stanza_get_text(topic);
        from = xmpp_stanza_get_from(stanza);
        if (from == NULL)
            return 1;
        from_bare = xmpp_jid_bare(account->context, from);
        from = xmpp_jid_resource(account->context, from);
        channel = channel__search(account, from_bare);
        if (!channel)
            channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);
        channel__update_topic(channel, intext ? intext : "", from, 0);
        if (intext != NULL)
            xmpp_free(account->context, intext);
        return 1;
    }
    type = xmpp_stanza_get_type(stanza);
    if (type != NULL && strcmp(type, "error") == 0)
        return 1;
    from = xmpp_stanza_get_from(stanza);
    if (from == NULL)
        return 1;
    from_bare = xmpp_jid_bare(account->context, from);
    to = xmpp_stanza_get_to(stanza);

    intext = xmpp_stanza_get_text(body);

    channel = channel__search(account, from_bare);
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
    delay = xmpp_stanza_get_child_by_name_and_ns(stanza, "delay", "urn:xmpp:delay");
    timestamp = delay ? xmpp_stanza_get_attribute(delay, "stamp") : NULL;
    if (timestamp)
    {
        strptime(timestamp, "%FT%T", &time);
        date = mktime(&time);
    }

    if (strcmp(to, channel->id) == 0)
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s[to %s]: %s",
                                 user__as_prefix_raw(account, from),
                                 to, intext ? intext : "");
    else if (weechat_string_match(intext, "/me *", 0))
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s%s %s",
                                 weechat_prefix("action"), from,
                                 intext ? intext+4 : "");
    else
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s%s",
                                 user__as_prefix_raw(account, from),
                                 intext ? intext : "");

    if (intext)
        xmpp_free(account->context, intext);

    return 1;
}

int connection__iq_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void) conn;

    struct t_account *account = (struct t_account *)userdata;
    xmpp_stanza_t *reply, *query, *identity, *feature, *x, *field, *value, *text;
    const char *node;
    static struct utsname osinfo;

    char *client_name = weechat_string_eval_expression("weechat ${info:version}",
                                                       NULL, NULL, NULL);

    reply = xmpp_stanza_reply(stanza);
    xmpp_stanza_set_type(reply, "result");

    query = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "query", "http://jabber.org/protocol/disco#info");
    node = xmpp_stanza_get_attribute(query, "node");
    xmpp_stanza_set_attribute(reply, "id", node);

    identity = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(identity, "identity");
    xmpp_stanza_set_attribute(identity, "category", "client");
    xmpp_stanza_set_attribute(identity, "name", client_name);
    xmpp_stanza_set_attribute(identity, "type", "pc");
    xmpp_stanza_add_child(query, identity);
    xmpp_stanza_release(identity);

#define FEATURE(ns) \
    feature = xmpp_stanza_new(account->context); \
    xmpp_stanza_set_name(feature, "feature"); \
    xmpp_stanza_set_attribute(feature, "var", ns); \
    xmpp_stanza_add_child(query, feature); \
    xmpp_stanza_release(feature);

    FEATURE("http://jabber.org/protocol/caps");
    FEATURE("http://jabber.org/protocol/disco#info");
    FEATURE("http://jabber.org/protocol/disco#items");
    FEATURE("http://jabber.org/protocol/muc");
    FEATURE("eu.siacs.conversations.axolotl.devicelist");
    FEATURE("eu.siacs.conversations.axolotl.devicelist+notify");
#undef FEATURE

    x = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(x, "x");
    xmpp_stanza_set_ns(x, "jabber:x:data");
    xmpp_stanza_set_attribute(x, "type", "result");

    if (uname(&osinfo) < 0)
    {
        *osinfo.sysname = 0;
        *osinfo.release = 0;
    }

    {
        field = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "FORM_TYPE");
        xmpp_stanza_set_attribute(field, "type", "hidden");

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, "urn:xmpp:dataforms:softwareinfo");
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    {
        field = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "ip_version");
        xmpp_stanza_set_attribute(field, "type", "text-multi");

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, "ipv4");
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, "ipv6");
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    {
        field = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "os");

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, osinfo.sysname);
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    {
        field = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "os_version");

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, osinfo.release);
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    {
        field = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "software");

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, "weechat");
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    {
        field = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "software_version");

        value = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(text, weechat_info_get("version", NULL));
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    xmpp_stanza_add_child(query, x);
    xmpp_stanza_release(x);

    xmpp_stanza_add_child(reply, query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);

    free(client_name);

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
        xmpp_stanza_t *pres, *pres__c, *pres__status, *pres__status__text, **children;
        char cap_hash[28+1] = {0};

        xmpp_handler_add(conn, connection__version_handler,
                         "jabber:iq:version", "iq", NULL, account);
        xmpp_handler_add(conn, connection__presence_handler,
                         NULL, "presence", NULL, account);
        xmpp_handler_add(conn, connection__message_handler,
                         NULL, "message", /*type*/ NULL, account);
        xmpp_handler_add(conn, connection__iq_handler,
                         NULL, "iq", "get", account);

        /* Send initial <presence/> so that we appear online to contacts */
        children = malloc(sizeof(*children) * (2 + 1));

        pres__c = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(pres__c, "c");
        xmpp_stanza_set_ns(pres__c, "http://jabber.org/protocol/caps");
        xmpp_stanza_set_attribute(pres__c, "hash", "sha-1");
        xmpp_stanza_set_attribute(pres__c, "node", "http://weechat.org");
        snprintf(cap_hash, sizeof(cap_hash), "%027ld=", time(NULL));
        xmpp_stanza_set_attribute(pres__c, "ver", cap_hash);
        children[0] = pres__c;

        pres__status = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(pres__status, "status");

        pres__status__text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(pres__status__text, account_status(account));
        xmpp_stanza_add_child(pres__status, pres__status__text);
        xmpp_stanza_release(pres__status__text);

        children[1] = pres__status;

        children[2] = NULL;
        pres = stanza__presence(account->context, NULL,
                                children, NULL, strdup(account_jid(account)),
                                NULL, NULL);
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);

        char **command = weechat_string_dyn_alloc(256);
        weechat_string_dyn_concat(command, "/enter ", -1);
        weechat_string_dyn_concat(command, account_autojoin(account), -1);
        weechat_command(account->buffer, *command);
        weechat_string_dyn_free(command, 1);

        omemo__init(account);
    } else {
        account__disconnect(account, 1);
      //xmpp_stop(account->context); //keep context?
    }
}

char* connection__rand_string(int length)
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
    static const unsigned ka_timeout_sec = 60;
    static const unsigned ka_timeout_ivl = 1;

    *connection = xmpp_conn_new(account->context);

    xmpp_conn_set_keepalive(*connection, ka_timeout_sec, ka_timeout_ivl);

    const char *resource = account_resource(account);
    if (!(resource && strlen(resource)))
    {
        char *const rand = connection__rand_string(8);
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

    int flags = xmpp_conn_get_flags(*connection);
    switch (tls)
    {
        case 0:
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
            break;
        case 1:
            flags &= ~XMPP_CONN_FLAG_DISABLE_TLS;
            flags &= ~XMPP_CONN_FLAG_TRUST_TLS;
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
