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
#include "diff/diff.h"
#include "xmpp/stanza.h"
#include "config.h"
#include "account.h"
#include "user.h"
#include "channel.h"
#include "connection.h"
#include "omemo.h"
#include "util.h"

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
    xmpp_stanza_t *iq__x, *iq__x__item, *iq__c, *iq__status;
    const char *from, *from_bare, *role = NULL, *affiliation = NULL, *jid = NULL;
    const char *node = NULL, *ver = NULL;
    char *clientid = NULL, *status;

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
        jid = xmpp_stanza_get_attribute(iq__x__item, "jid");
    }
    iq__c = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "c", "http://jabber.org/protocol/caps");
    if (iq__c)
    {
        node = xmpp_stanza_get_attribute(iq__c, "node");
        ver = xmpp_stanza_get_attribute(iq__c, "ver");
        if (jid)
            clientid = strdup(jid);
        else if (node && ver)
        {
            int len = strlen(node)+1+strlen(ver);
            clientid = malloc(sizeof(char)*len);
            snprintf(clientid, len, "%s#%s", node, ver);
        }
    }
    iq__status = xmpp_stanza_get_child_by_name(stanza, "status");
    status = iq__status ? xmpp_stanza_get_text(iq__status) : NULL;

    user = user__search(account, from);
    if (!user)
        user = user__new(account, from, from);

    channel = channel__search(account, from_bare);
    if (!iq__x)
    {
        if (!channel)
            channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);
        channel__add_member(account, channel, from, clientid, status);
    }
    else if (channel)
    {
        channel__set_member_role(account, channel, from, role);
        channel__set_member_affiliation(account, channel, from, affiliation);
        if (weechat_strcasecmp(role, "none") == 0)
            channel__remove_member(account, channel, from, status);
        else
            channel__add_member(account, channel, from, clientid, status);
    }

    if (clientid)
        free(clientid);

    return 1;
}

int connection__message_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void) conn;

    struct t_account *account = (struct t_account *)userdata;
    struct t_channel *channel;
    xmpp_stanza_t *body, *delay, *topic, *replace;
    const char *type, *from, *nick, *from_bare, *to, *id, *replace_id, *timestamp;
    char *intext, *difftext = NULL;
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
    id = xmpp_stanza_get_id(stanza);
    replace = xmpp_stanza_get_child_by_name_and_ns(stanza, "replace", "urn:xmpp:message-correct:0");
    replace_id = replace ? xmpp_stanza_get_id(replace) : NULL;

    intext = xmpp_stanza_get_text(body);

    channel = channel__search(account, from_bare);
    if (!channel)
        channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);
    if (replace)
    {
        const char *orig = NULL;
        void *lines = weechat_hdata_pointer(weechat_hdata_get("buffer"),
                                            channel->buffer, "lines");
        if (lines)
        {
            void *last_line = weechat_hdata_pointer(weechat_hdata_get("lines"),
                                                    lines, "last_line");
            while (last_line && !orig)
            {
                void *line_data = weechat_hdata_pointer(weechat_hdata_get("line"),
                                                        last_line, "data");
                if (line_data)
                {
                    int tags_count = weechat_hdata_integer(weechat_hdata_get("line_data"),
                                                           line_data, "tags_count");
                    char str_tag[20] = {0};
                    for (int n_tag = 0; n_tag < tags_count; n_tag++)
                    {
                        snprintf(str_tag, sizeof(str_tag), "%d|tags_array", n_tag);
                        const char *tag = weechat_hdata_string(weechat_hdata_get("line_data"),
                                                               line_data, str_tag);
                        if (strlen(tag) > strlen("id_") &&
                            weechat_strcasecmp(tag+strlen("id_"), replace_id) == 0)
                        {
                            struct t_arraylist *orig_lines = weechat_arraylist_new(
                                0, 0, 0, NULL, NULL, NULL, NULL);
                            char *msg = (char*)weechat_hdata_string(weechat_hdata_get("line_data"),
                                                                    line_data, "message");
                            weechat_arraylist_insert(orig_lines, 0, msg);

                            while (msg)
                            {
                                last_line = weechat_hdata_pointer(weechat_hdata_get("line"),
                                                                  last_line, "prev_line");
                                if (last_line)
                                    line_data = weechat_hdata_pointer(weechat_hdata_get("line"),
                                                                      last_line, "data");
                                else
                                    line_data = NULL;

                                msg = NULL;
                                if (line_data)
                                {
                                    tags_count = weechat_hdata_integer(weechat_hdata_get("line_data"),
                                                                       line_data, "tags_count");
                                    for (n_tag = 0; n_tag < tags_count; n_tag++)
                                    {
                                        snprintf(str_tag, sizeof(str_tag), "%d|tags_array", n_tag);
                                        tag = weechat_hdata_string(weechat_hdata_get("line_data"),
                                                                   line_data, str_tag);
                                        if (strlen(tag) > strlen("id_") &&
                                            weechat_strcasecmp(tag+strlen("id_"), replace_id) == 0)
                                        {
                                            msg = (char*)weechat_hdata_string(weechat_hdata_get("line_data"),
                                                                              line_data, "message");
                                            break;
                                        }
                                    }
                                }

                                if (msg)
                                    weechat_arraylist_insert(orig_lines, 0, msg);
                            }

                            char **orig_message = weechat_string_dyn_alloc(256);
                            for (int i = 0; i < weechat_arraylist_size(orig_lines); i++)
                                weechat_string_dyn_concat(orig_message,
                                                          weechat_arraylist_get(orig_lines, i),
                                                          -1);
                            orig = *orig_message;
                            weechat_string_dyn_free(orig_message, 0);
                            break;
                        }
                    }
                }

                last_line = weechat_hdata_pointer(weechat_hdata_get("line"),
                                                  last_line, "prev_line");
            }
        }

        if (orig)
        {
            struct diff result;
            if (diff(&result, char_cmp, 1, orig, strlen(orig), intext, strlen(intext)) > 0)
            {
                char **visual = weechat_string_dyn_alloc(256);
                char ch[2] = {0};

                for (size_t i = 0; i < result.sessz; i++)
                    switch (result.ses[i].type)
                    {
                        case DIFF_ADD:
                            weechat_string_dyn_concat(visual, weechat_color("green"), -1);
                            *ch = *(const char *)result.ses[i].e;
                            weechat_string_dyn_concat(visual, ch, -1);
                            break;
                        case DIFF_DELETE:
                            weechat_string_dyn_concat(visual, weechat_color("red"), -1);
                            *ch = *(const char *)result.ses[i].e;
                            weechat_string_dyn_concat(visual, ch, -1);
                            break;
                        case DIFF_COMMON:
                        default:
                            weechat_string_dyn_concat(visual, weechat_color("resetcolor"), -1);
                            *ch = *(const char *)result.ses[i].e;
                            weechat_string_dyn_concat(visual, ch, -1);
                            break;
                    }
                free(result.ses);
                free(result.lcs);

                difftext = strdup(*visual);
                weechat_string_dyn_free(visual, 1);
            }
        }
    }

    nick = NULL;
    if (weechat_strcasecmp(type, "groupchat") == 0)
    {
        nick = weechat_strcasecmp(channel->name,
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

    char **dyn_tags = weechat_string_dyn_alloc(1);
    weechat_string_dyn_concat(dyn_tags, "xmpp_message,message", -1);
    {
        weechat_string_dyn_concat(dyn_tags, ",nick_", -1);
        weechat_string_dyn_concat(dyn_tags, nick, -1);
    }
    {
        weechat_string_dyn_concat(dyn_tags, ",host_", -1);
        weechat_string_dyn_concat(dyn_tags, from, -1);
    }
    if (id)
    {
        weechat_string_dyn_concat(dyn_tags, ",id_", -1);
        weechat_string_dyn_concat(dyn_tags, id, -1);
    }

    if (strcmp(to, channel->id) == 0)
        weechat_string_dyn_concat(dyn_tags, ",private", -1);
    if (weechat_string_match(intext, "/me *", 0))
        weechat_string_dyn_concat(dyn_tags, ",action", -1);
    if (replace)
    {
        weechat_string_dyn_concat(dyn_tags, ",edit", -1);
        weechat_string_dyn_concat(dyn_tags, ",replace_", -1);
        weechat_string_dyn_concat(dyn_tags, replace_id, -1);
    }

    if (date != 0)
        weechat_string_dyn_concat(dyn_tags, ",notify_none", -1);
    else
        weechat_string_dyn_concat(dyn_tags, ",log1", -1);

    const char *edit = replace ? "* " : ""; // Losing which message was edited, sadly
    if (strcmp(to, channel->id) == 0)
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t[to %s]: %s",
                                 edit, user__as_prefix_raw(account, nick),
                                 to, difftext ? difftext : intext ? intext : "");
    else if (weechat_string_match(intext, "/me *", 0))
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t%s %s",
                                 edit, weechat_prefix("action"), nick,
                                 difftext ? difftext+4 : intext ? intext+4 : "");
    else
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t%s",
                                 edit, user__as_prefix_raw(account, nick),
                                 difftext ? difftext : intext ? intext : "");

    weechat_string_dyn_free(dyn_tags, 1);

    if (intext)
        xmpp_free(account->context, intext);
    if (difftext)
        free(difftext);

    return 1;
}

int connection__iq_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void) conn;

    struct t_account *account = (struct t_account *)userdata;
    xmpp_stanza_t *reply, *query, *identity, *feature, *enable, *x, *field, *value, *text;
    xmpp_stanza_t         *pubsub, *items, *item, *list, *device, **children;
    xmpp_stanza_t         *storage, *conference, *nick;
    static struct utsname osinfo;

    query = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "query", "http://jabber.org/protocol/disco#info");
    const char *type = xmpp_stanza_get_attribute(stanza, "type");
    if (query && type && weechat_strcasecmp(type, "get") == 0)
    {
        char *client_name;

        reply = xmpp_stanza_reply(stanza);
        xmpp_stanza_set_type(reply, "result");

        client_name = weechat_string_eval_expression("weechat ${info:version}",
                                                     NULL, NULL, NULL);

        identity = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(identity, "identity");
        xmpp_stanza_set_attribute(identity, "category", "client");
        xmpp_stanza_set_attribute(identity, "name", client_name);
        xmpp_stanza_set_attribute(identity, "type", "pc");
        xmpp_stanza_add_child(query, identity);
        xmpp_stanza_release(identity);

#define FEATURE(ns)                                     \
        feature = xmpp_stanza_new(account->context);    \
        xmpp_stanza_set_name(feature, "feature");       \
        xmpp_stanza_set_attribute(feature, "var", ns);  \
        xmpp_stanza_add_child(query, feature);          \
        xmpp_stanza_release(feature);

        FEATURE("eu.siacs.conversations.axolotl.devicelist+notify");
        FEATURE("http://jabber.org/protocol/caps");
        FEATURE("http://jabber.org/protocol/chatstates");
        FEATURE("http://jabber.org/protocol/disco#info");
        FEATURE("http://jabber.org/protocol/disco#items");
        FEATURE("http://jabber.org/protocol/muc");
        FEATURE("http://jabber.org/protocol/nick+notify");
        FEATURE("jabber:iq:version");
        FEATURE("jabber:x:conference");
        FEATURE("jabber:x:oob");
        FEATURE("storage:bookmarks+notify");
        FEATURE("urn:xmpp:avatar:metadata+notify");
        FEATURE("urn:xmpp:chat-markers:0");
        FEATURE("urn:xmpp:idle:1");
      //FEATURE("urn:xmpp:jingle-message:0");
      //FEATURE("urn:xmpp:jingle:1");
      //FEATURE("urn:xmpp:jingle:apps:dtls:0");
      //FEATURE("urn:xmpp:jingle:apps:file-transfer:3");
      //FEATURE("urn:xmpp:jingle:apps:file-transfer:4");
      //FEATURE("urn:xmpp:jingle:apps:file-transfer:5");
      //FEATURE("urn:xmpp:jingle:apps:rtp:1");
      //FEATURE("urn:xmpp:jingle:apps:rtp:audio");
      //FEATURE("urn:xmpp:jingle:apps:rtp:video");
      //FEATURE("urn:xmpp:jingle:jet-omemo:0");
      //FEATURE("urn:xmpp:jingle:jet:0");
      //FEATURE("urn:xmpp:jingle:transports:ibb:1");
      //FEATURE("urn:xmpp:jingle:transports:ice-udp:1");
      //FEATURE("urn:xmpp:jingle:transports:s5b:1");
        FEATURE("urn:xmpp:message-correct:0");
        FEATURE("urn:xmpp:ping");
        FEATURE("urn:xmpp:receipts");
        FEATURE("urn:xmpp:time");
#undef FEATURE

        enable = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(enable, "enable");
        xmpp_stanza_set_ns(enable, "urn:xmpp:carbons:2");
        xmpp_stanza_add_child(query, enable);
        xmpp_stanza_release(enable);

        x = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(x, "x");
        xmpp_stanza_set_ns(x, "jabber:x:data");
        xmpp_stanza_set_attribute(x, "type", "result");

        if (uname(&osinfo) < 0)
        {
            *osinfo.sysname = 0;
            *osinfo.release = 0;
        }

        // This is utter bullshit, TODO: anything but this.
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
    }

    pubsub = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "pubsub", "http://jabber.org/protocol/pubsub");
    if (pubsub)
    {
        const char *items_node, *item_id, *device_id, *ns, *node;

        items = xmpp_stanza_get_child_by_name(pubsub, "items");
        if (items)
        {
            items_node = xmpp_stanza_get_attribute(items, "node");
            if (items_node
                && weechat_strcasecmp(items_node,
                                      "eu.siacs.conversations.axolotl.devicelist") == 0)
            {
                item = xmpp_stanza_get_child_by_name(items, "item");
                if (item)
                    item_id = xmpp_stanza_get_id(item);
                if (item && item_id && weechat_strcasecmp(item_id, "current") == 0)
                {
                    list = xmpp_stanza_get_child_by_name_and_ns(
                        item, "list", "eu.siacs.conversations.axolotl");
                    if (list)
                    {
                        account__free_device_all(account);

                        struct t_device *dev = malloc(sizeof(dev));
                        char id[64] = {0};

                        dev->id = account->omemo->device_id;
                        snprintf(id, sizeof(id), "%d", dev->id);
                        dev->name = strdup(id);
                        account__add_device(account, dev);

                        int i = 0;
                        children = malloc(sizeof(xmpp_stanza_t *) * 128);
                        children[i++] = stanza__iq_pubsub_publish_item_list_device(
                            account->context, NULL, with_noop(dev->name));

                        free(dev->name);
                        free(dev);

                        for (device = xmpp_stanza_get_children(list);
                             device; device = xmpp_stanza_get_next(device))
                        {
                            const char *name = xmpp_stanza_get_name(device);
                            if (weechat_strcasecmp(name, "device") != 0)
                                continue;

                            device_id = xmpp_stanza_get_id(device);

                            dev = malloc(sizeof(dev));
                            dev->id = atoi(device_id);
                            dev->name = strdup(device_id);
                            account__add_device(account, dev);

                            children[i++] = stanza__iq_pubsub_publish_item_list_device(
                                account->context, NULL, with_noop(dev->name));

                            free(dev->name);
                            free(dev);
                        }

                        children[i] = NULL;
                        node = "eu.siacs.conversations.axolotl";
                        children[0] = stanza__iq_pubsub_publish_item_list(
                            account->context, NULL, children, with_noop(node));
                        children[1] = NULL;
                        children[0] = stanza__iq_pubsub_publish_item(
                            account->context, NULL, children, with_noop("current"));
                        ns = "http://jabber.org/protocol/pubsub";
                        children[0] = stanza__iq_pubsub_publish(account->context,
                                                                NULL, children,
                                                                with_noop(ns));
                        children[0] = stanza__iq_pubsub(account->context, NULL,
                                                        children, with_noop(""));
                        reply = stanza__iq(account->context, xmpp_stanza_reply(stanza),
                                           children, NULL, strdup("announce1"),
                                           NULL, NULL, strdup("set"));

                        xmpp_send(conn, reply);
                        xmpp_stanza_release(reply);

                        char bundle_node[128] = {0};
                        snprintf(bundle_node, sizeof(bundle_node),
                                 "eu.siacs.conversations.axolotl.bundles:%d",
                                 account->omemo->device_id);

                        children[1] = NULL;
                        children[0] = NULL;
                        ns = "eu.siacs.conversations.axolotl";
                        children[0] = stanza__iq_pubsub_publish_item_bundle(
                            account->context, NULL, NULL, with_noop(ns));
                        children[1] = NULL;
                        children[0] = stanza__iq_pubsub_publish_item(
                            account->context, NULL, children, with_noop("current"));
                        children[0] = stanza__iq_pubsub_publish(account->context,
                                                                NULL, children,
                                                                with_noop(bundle_node));
                        children[0] =
                            stanza__iq_pubsub(account->context, NULL, children,
                                              with_noop("http://jabber.org/protocol/pubsub"));
                        children[0] =
                            stanza__iq(account->context, NULL, children, NULL, strdup("announce2"),
                                       strdup(account_jid(account)), strdup(account_jid(account)),
                                       strdup("set"));

                        xmpp_send(conn, children[0]);
                        xmpp_stanza_release(children[0]);

                        free(children);
                    }
                }
            }
            if (items_node
                && weechat_strcasecmp(items_node, "storage:bookmarks") == 0)
            {
                item = xmpp_stanza_get_child_by_name(items, "item");
                if (item)
                    item_id = xmpp_stanza_get_id(item);
                if (item && item_id && weechat_strcasecmp(item_id, "current") == 0)
                {
                    storage = xmpp_stanza_get_child_by_name_and_ns(
                        item, "storage", "storage:bookmarks");
                    if (storage)
                    {
                        for (conference = xmpp_stanza_get_children(storage);
                             conference; conference = xmpp_stanza_get_next(conference))
                        {
                            const char *name = xmpp_stanza_get_name(conference);
                            if (weechat_strcasecmp(name, "conference") != 0)
                                continue;

                            const char *jid = xmpp_stanza_get_attribute(conference, "jid");
                            const char *autojoin = xmpp_stanza_get_attribute(conference, "autojoin");
                            name = xmpp_stanza_get_attribute(conference, "name");
                            nick = xmpp_stanza_get_child_by_name(conference, "nick");
                            char *intext;
                            if (nick)
                            {
                                text = xmpp_stanza_get_children(nick);
                                intext = xmpp_stanza_get_text(text);
                            }

                            if (weechat_strcasecmp(autojoin, "true") == 0)
                            {
                                char **command = weechat_string_dyn_alloc(256);
                                weechat_string_dyn_concat(command, "/enter ", -1);
                                weechat_string_dyn_concat(command, jid, -1);
                                if (nick)
                                {
                                    weechat_string_dyn_concat(command, "/", -1);
                                    weechat_string_dyn_concat(command, intext, -1);
                                }
                                weechat_command(account->buffer, *command);
                                weechat_string_dyn_free(command, 1);
                            }

                            if (nick)
                                free(intext);
                        }
                    }
                }
            }
        }
    }

    return 1;
}

void connection__handler(xmpp_conn_t *conn, xmpp_conn_event_t status,
                         int error, xmpp_stream_error_t *stream_error,
                         void *userdata)
{
    struct t_account *account = (struct t_account *)userdata;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT)
    {
        xmpp_stanza_t *pres, *pres__c, *pres__status, *pres__status__text, **children;
        char cap_hash[28+1] = {0};

        xmpp_handler_add(conn, &connection__version_handler,
                         "jabber:iq:version", "iq", NULL, account);
        xmpp_handler_add(conn, &connection__presence_handler,
                         NULL, "presence", NULL, account);
        xmpp_handler_add(conn, &connection__message_handler,
                         NULL, "message", /*type*/ NULL, account);
      //xmpp_handler_add(conn, &connection__iq_handler,
      //                 NULL, "iq", "get", account);
        xmpp_handler_add(conn, &connection__iq_handler,
                         NULL, "iq", NULL, account);

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

        children[1] = NULL;
        children[0] =
        stanza__iq_pubsub_items(account->context, NULL,
                                strdup("storage:bookmarks"));
        children[0] =
        stanza__iq_pubsub(account->context, NULL, children,
                          with_noop("http://jabber.org/protocol/pubsub"));
        children[0] =
        stanza__iq(account->context, NULL, children, NULL, strdup("retrieve1"),
                   strdup(account_jid(account)), strdup(account_jid(account)),
                   strdup("get"));

        xmpp_send(conn, children[0]);
        xmpp_stanza_release(children[0]);

        children[1] = NULL;
        children[0] =
        stanza__iq_pubsub_items(account->context, NULL,
                                strdup("eu.siacs.conversations.axolotl.devicelist"));
        children[0] =
        stanza__iq_pubsub(account->context, NULL, children,
                          with_noop("http://jabber.org/protocol/pubsub"));
        children[0] =
        stanza__iq(account->context, NULL, children, NULL, strdup("fetch1"),
                   strdup(account_jid(account)), strdup(account_jid(account)),
                   strdup("get"));

        xmpp_send(conn, children[0]);
        xmpp_stanza_release(children[0]);

        struct t_hashtable *variables = weechat_hashtable_new (8,
                                                              WEECHAT_HASHTABLE_STRING,
                                                              WEECHAT_HASHTABLE_STRING,
                                                              NULL, NULL);
        weechat_hashtable_set(variables, "account", account->name);
        char *dev_str = weechat_string_eval_expression(
            "${sec.data.xmpp_device_${account}}",
            NULL, variables, NULL);
        char *b64_id = weechat_string_eval_expression(
            "${sec.data.xmpp_identity_${account}}",
            NULL, variables, NULL);
        weechat_hashtable_free(variables);
        uint32_t dev_id = dev_str[0] ? atoi(dev_str) : 0;
        uint8_t identity[128] = {0};
        if (b64_id && *b64_id)
            weechat_string_base_decode(64, b64_id, (char*)identity);
        struct t_identity id_key = {
            .key = identity,
            .length = 4,
        };

        omemo__init(&account->omemo, dev_id, b64_id && *b64_id ? &id_key : NULL);

        char account_id[64] = {0};
        snprintf(account_id, sizeof(account_id), "%d", account->omemo->device_id);
        if (weechat_strcasecmp(dev_str, account_id) != 0)
        {
            char **command = weechat_string_dyn_alloc(256);
            weechat_string_dyn_concat(command, "/secure set ", -1);
            weechat_string_dyn_concat(command, "xmpp_device_", -1);
            weechat_string_dyn_concat(command, account->name, -1);
            weechat_string_dyn_concat(command, " ", -1);
            weechat_string_dyn_concat(command, account_id, -1);
            weechat_command(account->buffer, *command);
            weechat_string_dyn_free(command, 1);
        }
        char account_key[64] = {0};
        weechat_string_base_encode(64, (char*)account->omemo->identity.key,
                                   account->omemo->identity.length, account_key);
        if (weechat_strcasecmp(b64_id, account_key) != 0)
        {
            char **command = weechat_string_dyn_alloc(256);
            weechat_string_dyn_concat(command, "/secure set ", -1);
            weechat_string_dyn_concat(command, "xmpp_identity_", -1);
            weechat_string_dyn_concat(command, account->name, -1);
            weechat_string_dyn_concat(command, " ", -1);
            weechat_string_dyn_concat(command, account_key, -1);
            weechat_command(account->buffer, *command);
            weechat_string_dyn_free(command, 1);
        }
    }
    else
    {
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
