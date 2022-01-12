// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "xmpp/stanza.hh"
#include "config.hh"
#include "account.hh"
#include "user.hh"
#include "channel.hh"
#include "connection.hh"
#include "omemo.hh"
#include "pgp.hh"
#include "util.hh"
extern "C" {
#include "diff/diff.h"
}

void connection__init()
{
    srand(time(NULL));
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
    xmpp_stanza_t *pres__x_signed, *pres__x_muc_user, *show, *idle, *pres__x__item, *pres__c, *pres__status;
    const char *to, *from, *from_bare, *from_res, *type, *role = NULL, *affiliation = NULL, *jid = NULL;
    const char *show__text = NULL, *idle__since = NULL, *certificate = NULL, *node = NULL, *ver = NULL;
    char *clientid = NULL, *status;

    to = xmpp_stanza_get_to(stanza);
    from = xmpp_stanza_get_from(stanza);
    if (from == NULL)
        return 1;
    from_bare = xmpp_jid_bare(account->context, from);
    from_res = xmpp_jid_resource(account->context, from);
    type = xmpp_stanza_get_type(stanza);
    show = xmpp_stanza_get_child_by_name(stanza, "show");
    show__text = show ? xmpp_stanza_get_text(show) : NULL;
    idle = xmpp_stanza_get_child_by_name_and_ns(stanza, "idle", "urn:xmpp:idle:1");
    idle__since = idle ? xmpp_stanza_get_attribute(idle, "since") : NULL;
    pres__x_signed = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "x", "jabber:x:signed");
    if (pres__x_signed)
    {
        certificate = xmpp_stanza_get_text(pres__x_signed);
    }
    pres__c = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "c", "http://jabber.org/protocol/caps");
    if (pres__c)
    {
        node = xmpp_stanza_get_attribute(pres__c, "node");
        ver = xmpp_stanza_get_attribute(pres__c, "ver");
        if (node && ver)
        {
            int len = strlen(node)+1+strlen(ver) + 1;
            clientid = (char*)malloc(sizeof(char)*len);
            snprintf(clientid, len, "%s#%s", node, ver);

            xmpp_stanza_t *children[2] = {NULL};
            children[0] = stanza__iq_pubsub_items(account->context, NULL,
                    const_cast<char*>("eu.siacs.conversations.axolotl.devicelist"));
            children[0] = stanza__iq_pubsub(account->context, NULL,
                    children, with_noop("http://jabber.org/protocol/pubsub"));
            children[0] = stanza__iq(account->context, NULL, children, NULL,
                    strdup("fetch2"), to ? strdup(to) : NULL, strdup(from_bare),
                    strdup("get"));
            xmpp_send(conn, children[0]);
            xmpp_stanza_release(children[0]);
        }
    }
    pres__status = xmpp_stanza_get_child_by_name(stanza, "status");
    status = pres__status ? xmpp_stanza_get_text(pres__status) : NULL;
    pres__x_muc_user = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "x", "http://jabber.org/protocol/muc#user");

    channel = channel__search(account, from_bare);
    if (weechat_strcasecmp(type, "unavailable") != 0 && !pres__x_muc_user && !channel)
        channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);

    if (pres__x_muc_user)
    for (pres__x__item = xmpp_stanza_get_children(pres__x_muc_user);
         pres__x__item; pres__x__item = xmpp_stanza_get_next(pres__x__item))
    {
        const char *pres__x__item__name = xmpp_stanza_get_name(pres__x__item);
        if (weechat_strcasecmp(pres__x__item__name, "item") != 0)
        {
            if (weechat_strcasecmp(pres__x__item__name, "status") == 0)
            {
                const char *pres__x__status__code = xmpp_stanza_get_attribute(
                        pres__x__item, "code");
                switch (strtol(pres__x__status__code, NULL, 10))
                {
                    case 100: // Non-Anonymous: [message | Entering a room]: Inform user that any occupant is allowed to see the user's full JID
                        weechat_buffer_set(channel->buffer, "notify", "2");
                        break;
                    case 101: // : [message (out of band) | Affiliation change]: Inform user that his or her affiliation changed while not in the room
                        break;
                    case 102: // : [message | Configuration change]: Inform occupants that room now shows unavailable members
                        break;
                    case 103: // : [message | Configuration change]: Inform occupants that room now does not show unavailable members
                        break;
                    case 104: // : [message | Configuration change]: Inform occupants that a non-privacy-related room configuration change has occurred
                        break;
                    case 110: // Self-Presence: [presence | Any room presence]: Inform user that presence refers to one of its own room occupants
                        break;
                    case 170: // Logging Active: [message or initial presence | Configuration change]: Inform occupants that room logging is now enabled
                        break;
                    case 171: // : [message | Configuration change]: Inform occupants that room logging is now disabled
                        break;
                    case 172: // : [message | Configuration change]: Inform occupants that the room is now non-anonymous
                        break;
                    case 173: // : [message | Configuration change]: Inform occupants that the room is now semi-anonymous
                        break;
                    case 174: // : [message | Configuration change]: Inform occupants that the room is now fully-anonymous
                        break;
                    case 201: // : [presence | Entering a room]: Inform user that a new room has been created
                        break;
                    case 210: // Nick Modified: [presence | Entering a room]: Inform user that the service has assigned or modified the occupant's roomnick
                        break;
                    case 301: // : [presence | Removal from room]: Inform user that he or she has been banned from the room
                        break;
                    case 303: // : [presence | Exiting a room]: Inform all occupants of new room nickname
                        break;
                    case 307: // : [presence | Removal from room]: Inform user that he or she has been kicked from the room
                        break;
                    case 321: // : [presence | Removal from room]: Inform user that he or she is being removed from the room because of an affiliation change
                        break;
                    case 322: // : [presence | Removal from room]: Inform user that he or she is being removed from the room because the room has been changed to members-only and the user is not a member
                        break;
                    case 332: // : [presence | Removal from room]: Inform user that he or she is being removed from the room because of a system shutdown
                        break;
                    default:
                        break;
                }
            }
            continue;
        }

        role = xmpp_stanza_get_attribute(pres__x__item, "role");
        affiliation = xmpp_stanza_get_attribute(pres__x__item, "affiliation");
        jid = xmpp_stanza_get_attribute(pres__x__item, "jid");

        user = user__search(account, from);
        if (!user)
            user = user__new(account, from,
                             channel && weechat_strcasecmp(from_bare, channel->id) == 0
                             ? from_res : from);
        user->profile.status_text = status ? strdup(status) : NULL;
        user->profile.status = show ? strdup(show__text) : NULL;
        user->profile.idle = idle ? strdup(idle__since) : NULL;
        user->is_away = show ? weechat_strcasecmp(show__text, "away") == 0 : 0;
        user->profile.role = role ? strdup(role) : NULL;
        user->profile.affiliation = affiliation && strcmp(affiliation, "none") != 0
            ? strdup(affiliation) : NULL;
        if (certificate && channel)
        {
            user->profile.pgp_id = pgp__verify(channel->buffer, account->pgp, certificate);
            if (channel->type != CHANNEL_TYPE_MUC)
                channel->pgp.id = user->profile.pgp_id;
        }

        if (channel)
        {
            if (weechat_strcasecmp(role, "none") == 0)
                channel__remove_member(account, channel, from, status);
            else
                channel__add_member(account, channel, from, jid ? jid : clientid);
        }
    }
    else
    {
        user = user__search(account, from);
        if (!user)
            user = user__new(account, from,
                             channel && weechat_strcasecmp(from_bare, channel->id) == 0
                             ? from_res : from);
        user->profile.status_text = status ? strdup(status) : NULL;
        user->profile.status = show ? strdup(show__text) : NULL;
        user->profile.idle = idle ? strdup(idle__since) : NULL;
        user->is_away = show ? weechat_strcasecmp(show__text, "away") == 0 : 0;
        user->profile.role = role ? strdup(role) : NULL;
        user->profile.affiliation = affiliation && strcmp(affiliation, "none") != 0
            ? strdup(affiliation) : NULL;
        if (certificate && channel)
        {
            user->profile.pgp_id = pgp__verify(channel->buffer, account->pgp, certificate);
            if (channel->type != CHANNEL_TYPE_MUC)
                channel->pgp.id = user->profile.pgp_id;
        }

        if (channel)
        {
            if (weechat_strcasecmp(type, "unavailable") == 0)
                channel__remove_member(account, channel, from, status);
            else
                channel__add_member(account, channel, from, clientid);
        }
    }

    if (clientid)
        free(clientid);

    return 1;
}

int connection__message_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void) conn;

    struct t_account *account = (struct t_account *)userdata;
    struct t_channel *channel, *parent_channel;
    xmpp_stanza_t *x, *body, *delay, *topic, *replace, *request, *markable, *composing, *sent, *received, *result, *forwarded, *event, *items, *item, *list, *device, *encrypted, **children;
    const char *type, *from, *nick, *from_bare, *to, *to_bare, *id, *thread, *replace_id, *timestamp;
    char *text, *intext, *difftext = NULL, *cleartext = NULL;
    struct tm time = {0};
    time_t date = 0;

    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL)
    {
        topic = xmpp_stanza_get_child_by_name(stanza, "subject");
        if (topic != NULL)
        {
            intext = xmpp_stanza_get_text(topic);
            type = xmpp_stanza_get_type(stanza);
            if (type != NULL && strcmp(type, "error") == 0)
                return 1;
            from = xmpp_stanza_get_from(stanza);
            if (from == NULL)
                return 1;
            from_bare = xmpp_jid_bare(account->context, from);
            from = xmpp_jid_resource(account->context, from);
            channel = channel__search(account, from_bare);
            if (!channel)
            {
                if (weechat_strcasecmp(type, "groupchat") == 0)
                    channel = channel__new(account, CHANNEL_TYPE_MUC, from_bare, from_bare);
                else
                    channel = channel__new(account, CHANNEL_TYPE_PM, from_bare, from_bare);
            }
            channel__update_topic(channel, intext ? intext : "", from, 0);
            if (intext != NULL)
                xmpp_free(account->context, intext);
        }

        composing = xmpp_stanza_get_child_by_name_and_ns(
            stanza, "composing", "http://jabber.org/protocol/chatstates");
        if (composing != NULL)
        {
            from = xmpp_stanza_get_from(stanza);
            if (from == NULL)
                return 1;
            from_bare = xmpp_jid_bare(account->context, from);
            nick = xmpp_jid_resource(account->context, from);
            channel = channel__search(account, from_bare);
            if (!channel)
                return 1;
            struct t_user *user = user__search(account, from);
            if (!user)
                user = user__new(account, from,
                                 weechat_strcasecmp(from_bare, channel->id) == 0
                                 ? nick : from);
            channel__add_typing(channel, user);
            weechat_printf(channel->buffer, "...\t%s%s typing",
                           weechat_color("gray"),
                           channel->type == CHANNEL_TYPE_MUC ? nick : from);
        }

        sent = xmpp_stanza_get_child_by_name_and_ns(
            stanza, "sent", "urn:xmpp:carbons:2");
        if (sent)
            forwarded = xmpp_stanza_get_child_by_name_and_ns(
                sent, "forwarded", "urn:xmpp:forward:0");
        received = xmpp_stanza_get_child_by_name_and_ns(
            stanza, "received", "urn:xmpp:carbons:2");
        if (received)
            forwarded = xmpp_stanza_get_child_by_name_and_ns(
                received, "forwarded", "urn:xmpp:forward:0");
        if ((sent || received) && forwarded != NULL)
        {
            xmpp_stanza_t *message = xmpp_stanza_get_children(forwarded);
            return connection__message_handler(conn, message, userdata);
        }

        result = xmpp_stanza_get_child_by_name_and_ns(
            stanza, "result", "urn:xmpp:mam:2");
        if (result)
        {
            forwarded = xmpp_stanza_get_child_by_name_and_ns(
                result, "forwarded", "urn:xmpp:forward:0");
            if (forwarded != NULL)
            {
                xmpp_stanza_t *message = xmpp_stanza_get_child_by_name(forwarded, "message");
                if (message)
                {
                    message = xmpp_stanza_copy(message);
                    delay = xmpp_stanza_get_child_by_name_and_ns(
                        forwarded, "delay", "urn:xmpp:delay");
                    if (delay != NULL)
                        xmpp_stanza_add_child_ex(message, xmpp_stanza_copy(delay), 0);
                    int ret = connection__message_handler(conn, message, userdata);
                    xmpp_stanza_release(message);
                    return ret;
                }
            }
        }

        event = xmpp_stanza_get_child_by_name_and_ns(
            stanza, "event", "http://jabber.org/protocol/pubsub#event");
        if (event)
        {
            items = xmpp_stanza_get_child_by_name(event, "items");
            if (items)
            {
                const char *items_node = xmpp_stanza_get_attribute(items, "node");
                from = xmpp_stanza_get_from(stanza);
                to = xmpp_stanza_get_to(stanza);
                if (items_node
                    && weechat_strcasecmp(items_node,
                                          "eu.siacs.conversations.axolotl.devicelist") == 0)
                {
                    item = xmpp_stanza_get_child_by_name(items, "item");
                    if (item)
                    {
                        list = xmpp_stanza_get_child_by_name_and_ns(
                            item, "list", "eu.siacs.conversations.axolotl");
                        if (list)
                        {
                            if (account->omemo)
                            {
                                omemo__handle_devicelist(account->omemo,
                                        from ? from : account_jid(account), items);
                            }

                            children = (xmpp_stanza_t**)malloc(sizeof(*children) * (3 + 1));

                            for (device = xmpp_stanza_get_children(list);
                                 device; device = xmpp_stanza_get_next(device))
                            {
                                const char *name = xmpp_stanza_get_name(device);
                                if (weechat_strcasecmp(name, "device") != 0)
                                    continue;

                                const char *device_id = xmpp_stanza_get_id(device);

                                char bundle_node[128] = {0};
                                snprintf(bundle_node, sizeof(bundle_node),
                                         "eu.siacs.conversations.axolotl.bundles:%s",
                                         device_id);

                                children[1] = NULL;
                                children[0] =
                                stanza__iq_pubsub_items(account->context, NULL,
                                                        strdup(bundle_node));
                                children[0] =
                                stanza__iq_pubsub(account->context, NULL, children,
                                                  with_noop("http://jabber.org/protocol/pubsub"));
                                char *uuid = xmpp_uuid_gen(account->context);
                                children[0] =
                                stanza__iq(account->context, NULL, children, NULL, uuid,
                                            strdup(to), strdup(from), strdup("get"));
                                xmpp_free(account->context, uuid);

                                xmpp_send(conn, children[0]);
                                xmpp_stanza_release(children[0]);
                            }
                        }
                    }
                }
            }
        }

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
    if (to == NULL)
        to = account_jid(account);
    to_bare = to ? xmpp_jid_bare(account->context, to) : NULL;
    id = xmpp_stanza_get_id(stanza);
    thread = xmpp_stanza_get_attribute(stanza, "thread");
    replace = xmpp_stanza_get_child_by_name_and_ns(stanza, "replace",
                                                   "urn:xmpp:message-correct:0");
    replace_id = replace ? xmpp_stanza_get_id(replace) : NULL;
    request = xmpp_stanza_get_child_by_name_and_ns(stanza, "request",
                                                   "urn:xmpp:receipts");
    markable = xmpp_stanza_get_child_by_name_and_ns(stanza, "markable",
                                                    "urn:xmpp:chat-markers:0");

    const char *channel_id = weechat_strcasecmp(account_jid(account), from_bare)
        == 0 ? to_bare : from_bare;
    parent_channel = channel__search(account, channel_id);
    const char *pm_id = weechat_strcasecmp(account_jid(account), from_bare)
        == 0 ? to : from;
    channel = parent_channel;
    if (!channel)
        channel = channel__new(account,
                               weechat_strcasecmp(type, "groupchat") == 0
                               ? CHANNEL_TYPE_MUC : CHANNEL_TYPE_PM,
                               channel_id, channel_id);
    if (channel && channel->type == CHANNEL_TYPE_MUC
        && weechat_strcasecmp(type, "chat") == 0)
        channel = channel__new(account, CHANNEL_TYPE_PM,
                               pm_id, pm_id);

    if (id && (markable || request))
    {
        struct t_channel_unread *unread = (struct t_channel_unread *)malloc(sizeof(struct t_channel_unread));
        unread->id = strdup(id);
        unread->thread = thread ? strdup(thread) : NULL;

        xmpp_stanza_t *message = xmpp_message_new(account->context, NULL,
                                                  channel->id, NULL);

        if (request)
        {
            xmpp_stanza_t *message__received = xmpp_stanza_new(account->context);
            xmpp_stanza_set_name(message__received, "received");
            xmpp_stanza_set_ns(message__received, "urn:xmpp:receipts");
            xmpp_stanza_set_id(message__received, unread->id);

            xmpp_stanza_add_child(message, message__received);
            xmpp_stanza_release(message__received);
        }

        if (markable)
        {
            xmpp_stanza_t *message__received = xmpp_stanza_new(account->context);
            xmpp_stanza_set_name(message__received, "received");
            xmpp_stanza_set_ns(message__received, "urn:xmpp:chat-markers:0");
            xmpp_stanza_set_id(message__received, unread->id);

            xmpp_stanza_add_child(message, message__received);
            xmpp_stanza_release(message__received);
        }

        if (unread->thread)
        {
            xmpp_stanza_t *message__thread = xmpp_stanza_new(account->context);
            xmpp_stanza_set_name(message__thread, "thread");

            xmpp_stanza_t *message__thread__text = xmpp_stanza_new(account->context);
            xmpp_stanza_set_text(message__thread__text, unread->thread);
            xmpp_stanza_add_child(message__thread, message__thread__text);
            xmpp_stanza_release(message__thread__text);

            xmpp_stanza_add_child(message, message__thread);
            xmpp_stanza_release(message__thread);
        }

        xmpp_send(account->connection, message);
        xmpp_stanza_release(message);

        if (!channel->unreads)
            channel->unreads = weechat_list_new();
        weechat_list_add(channel->unreads, unread->id, WEECHAT_LIST_POS_END, unread);
    }

    encrypted = xmpp_stanza_get_child_by_name_and_ns(stanza, "encrypted",
                                                     "eu.siacs.conversations.axolotl");
    if (encrypted && account->omemo)
    {
        cleartext = omemo__decode(account, from_bare, encrypted);
    }
    x = xmpp_stanza_get_child_by_name_and_ns(stanza, "x", "jabber:x:encrypted");
    intext = xmpp_stanza_get_text(body);
    if (x)
    {
        char *ciphertext = xmpp_stanza_get_text(x);
        cleartext = pgp__decrypt(channel->buffer, account->pgp, ciphertext);
        xmpp_free(account->context, ciphertext);
    }
    text = cleartext ? cleartext : intext;

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
                                                          (const char*)weechat_arraylist_get(orig_lines, i),
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
            if (diff(&result, char_cmp, 1, orig, strlen(orig), text, strlen(text)) > 0)
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

    nick = from;
    if (weechat_strcasecmp(type, "groupchat") == 0)
    {
        nick = weechat_strcasecmp(channel->name,
                                  xmpp_jid_bare(account->context,
                                                from)) == 0
            ? xmpp_jid_resource(account->context, from)
            : from;
    }
    else if (parent_channel && parent_channel->type == CHANNEL_TYPE_MUC)
    {
        nick = weechat_strcasecmp(channel->name, from) == 0
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

    if (channel->type == CHANNEL_TYPE_PM)
        weechat_string_dyn_concat(dyn_tags, ",private", -1);
    if (weechat_string_match(text, "/me *", 0))
        weechat_string_dyn_concat(dyn_tags, ",xmpp_action", -1);
    if (replace)
    {
        weechat_string_dyn_concat(dyn_tags, ",edit", -1);
        weechat_string_dyn_concat(dyn_tags, ",replace_", -1);
        weechat_string_dyn_concat(dyn_tags, replace_id, -1);
    }

    if (date != 0 || encrypted)
        weechat_string_dyn_concat(dyn_tags, ",notify_none", -1);
    else if (channel->type == CHANNEL_TYPE_PM
             && weechat_strcasecmp(from_bare, account_jid(account)) != 0)
        weechat_string_dyn_concat(dyn_tags, ",notify_private", -1);
    else
        weechat_string_dyn_concat(dyn_tags, ",notify_message,log1", -1);

    const char *edit = replace ? "* " : ""; // Losing which message was edited, sadly
    if (x && text == cleartext && channel->transport != CHANNEL_TRANSPORT_PGP)
    {
        channel->transport = CHANNEL_TRANSPORT_PGP;
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s%sTransport: %s",
                                 weechat_prefix("network"), weechat_color("gray"),
                                 channel__transport_name(channel->transport));
    }
    else if (!x && text == intext && channel->transport != CHANNEL_TRANSPORT_PLAIN)
    {
        channel->transport = CHANNEL_TRANSPORT_PLAIN;
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s%sTransport: %s",
                                 weechat_prefix("network"), weechat_color("gray"),
                                 channel__transport_name(channel->transport));
    }
    if (channel_id == from_bare && strcmp(to, channel->id) == 0)
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t[to %s]: %s",
                                 edit, user__as_prefix_raw(account, nick),
                                 to, difftext ? difftext : text ? text : "");
    else if (weechat_string_match(text, "/me *", 0))
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t%s %s",
                                 edit, weechat_prefix("action"), user__as_prefix_raw(account, nick),
                                 difftext ? difftext+4 : text ? text+4 : "");
    else
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t%s",
                                 edit, user__as_prefix_raw(account, nick),
                                 difftext ? difftext : text ? text : "");

    weechat_string_dyn_free(dyn_tags, 1);

    if (intext)
        xmpp_free(account->context, intext);
    if (difftext)
        free(difftext);
    if (cleartext)
        free(cleartext);

    return 1;
}

xmpp_stanza_t *connection__get_caps(xmpp_stanza_t *reply, struct t_account *account, char **hash)
{
    xmpp_stanza_t *query = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(query, "query");
    xmpp_stanza_set_ns(query, "http://jabber.org/protocol/disco#info");

    char *client_name = weechat_string_eval_expression(
            "weechat ${info:version}", NULL, NULL, NULL);
    char **serial = weechat_string_dyn_alloc(256);
    weechat_string_dyn_concat(serial, "client/pc//", -1);
    weechat_string_dyn_concat(serial, client_name, -1);
    weechat_string_dyn_concat(serial, "<", -1);

    xmpp_stanza_t *identity = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(identity, "identity");
    xmpp_stanza_set_attribute(identity, "category", "client");
    xmpp_stanza_set_attribute(identity, "name", client_name);
    free(client_name);
    xmpp_stanza_set_attribute(identity, "type", "pc");
    xmpp_stanza_add_child(query, identity);
    xmpp_stanza_release(identity);

    xmpp_stanza_t *feature = NULL;

#define FEATURE(NS)                                 \
    feature = xmpp_stanza_new(account->context);    \
    xmpp_stanza_set_name(feature, "feature");       \
    xmpp_stanza_set_attribute(feature, "var", NS);  \
    xmpp_stanza_add_child(query, feature);          \
    xmpp_stanza_release(feature);                   \
    weechat_string_dyn_concat(serial, NS, -1);      \
    weechat_string_dyn_concat(serial, "<", -1);

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

    xmpp_stanza_t *x = xmpp_stanza_new(account->context);
    xmpp_stanza_set_name(x, "x");
    xmpp_stanza_set_ns(x, "jabber:x:data");
    xmpp_stanza_set_attribute(x, "type", "result");

    static struct utsname osinfo;
    if (uname(&osinfo) < 0)
    {
        *osinfo.sysname = 0;
        *osinfo.release = 0;
    }

    xmpp_stanza_t *field, *value, *text;
    // This is utter bullshit, TODO: anything but this.
#define FEATURE1(VAR, TYPE, VALUE)                            \
    field = xmpp_stanza_new(account->context);                \
    xmpp_stanza_set_name(field, "field");                     \
    xmpp_stanza_set_attribute(field, "var", VAR);             \
    if(TYPE) xmpp_stanza_set_attribute(field, "type", TYPE);  \
    value = xmpp_stanza_new(account->context);                \
    xmpp_stanza_set_name(value, "value");                     \
    text = xmpp_stanza_new(account->context);                 \
    xmpp_stanza_set_text(text, VALUE);                        \
    xmpp_stanza_add_child(value, text);                       \
    xmpp_stanza_release(text);                                \
    xmpp_stanza_add_child(field, value);                      \
    xmpp_stanza_release(value);                               \
    xmpp_stanza_add_child(x, field);                          \
    xmpp_stanza_release(field);                               \
    if (strcmp(VAR, "FORM_TYPE") == 0) {                      \
        weechat_string_dyn_concat(serial, VAR, -1);           \
        weechat_string_dyn_concat(serial, "<", -1);           \
    }                                                         \
    weechat_string_dyn_concat(serial, VALUE, -1);             \
    weechat_string_dyn_concat(serial, "<", -1);
#define FEATURE2(VAR, TYPE, VALUE1, VALUE2)                   \
    field = xmpp_stanza_new(account->context);                \
    xmpp_stanza_set_name(field, "field");                     \
    xmpp_stanza_set_attribute(field, "var", VAR);             \
    xmpp_stanza_set_attribute(field, "type", TYPE);           \
    value = xmpp_stanza_new(account->context);                \
    xmpp_stanza_set_name(value, "value");                     \
    text = xmpp_stanza_new(account->context);                 \
    xmpp_stanza_set_text(text, VALUE1);                       \
    xmpp_stanza_add_child(value, text);                       \
    xmpp_stanza_release(text);                                \
    xmpp_stanza_add_child(field, value);                      \
    xmpp_stanza_release(value);                               \
    value = xmpp_stanza_new(account->context);                \
    xmpp_stanza_set_name(value, "value");                     \
    text = xmpp_stanza_new(account->context);                 \
    xmpp_stanza_set_text(text, VALUE2);                       \
    xmpp_stanza_add_child(value, text);                       \
    xmpp_stanza_release(text);                                \
    xmpp_stanza_add_child(field, value);                      \
    xmpp_stanza_release(value);                               \
    xmpp_stanza_add_child(x, field);                          \
    xmpp_stanza_release(field);                               \
    weechat_string_dyn_concat(serial, VAR, -1);               \
    weechat_string_dyn_concat(serial, "<", -1);               \
    weechat_string_dyn_concat(serial, VALUE1, -1);            \
    weechat_string_dyn_concat(serial, "<", -1);               \
    weechat_string_dyn_concat(serial, VALUE2, -1);            \
    weechat_string_dyn_concat(serial, "<", -1);

    FEATURE1("FORM_TYPE", "hidden", "urn:xmpp:dataforms:softwareinfo");
    FEATURE2("ip_version", "text-multi", "ipv4", "ipv6");
    FEATURE1("os", NULL, osinfo.sysname);
    FEATURE1("os_version", NULL, osinfo.release);
    FEATURE1("software", NULL, "weechat");
    FEATURE1("software_version", NULL, weechat_info_get("version", NULL));
#undef FEATURE1
#undef FEATURE2

    xmpp_stanza_add_child(query, x);
    xmpp_stanza_release(x);

    xmpp_stanza_set_type(reply, "result");
    xmpp_stanza_add_child(reply, query);

    unsigned char digest[20];
    xmpp_sha1_t *sha1 = xmpp_sha1_new(account->context);
    xmpp_sha1_update(sha1, (unsigned char*)*serial, strlen(*serial));
    xmpp_sha1_final(sha1);
    weechat_string_dyn_free(serial, 1);
    xmpp_sha1_to_digest(sha1, digest);
    xmpp_sha1_free(sha1);

    if (hash)
    {
        char *cap_hash = xmpp_base64_encode(account->context, digest, 20);
        *hash = strdup(cap_hash);
        xmpp_free(account->context, cap_hash);
    }

    return reply;
}

int connection__iq_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    struct t_account *account = (struct t_account *)userdata;
    xmpp_stanza_t *reply, *query, *text, *fin;
    xmpp_stanza_t         *pubsub, *items, *item, *list, *bundle, *device;
    xmpp_stanza_t         *storage, *conference, *nick;

    const char *id = xmpp_stanza_get_id(stanza);
    const char *from = xmpp_stanza_get_from(stanza);
    const char *to = xmpp_stanza_get_to(stanza);
    query = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "query", "http://jabber.org/protocol/disco#info");
    const char *type = xmpp_stanza_get_attribute(stanza, "type");
    if (query && type)
    {
        if (weechat_strcasecmp(type, "get") == 0)
        {
            reply = connection__get_caps(xmpp_stanza_reply(stanza), account, NULL);

            xmpp_send(conn, reply);
            xmpp_stanza_release(reply);
        }

        if (weechat_strcasecmp(type, "result") == 0)
        {
        }
    }

    pubsub = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "pubsub", "http://jabber.org/protocol/pubsub");
    if (pubsub)
    {
        const char *items_node, *item_id, *device_id;

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
                {
                    item_id = xmpp_stanza_get_id(item);
                    list = xmpp_stanza_get_child_by_name_and_ns(
                        item, "list", "eu.siacs.conversations.axolotl");
                    if (list && account->omemo)
                    {
                        omemo__handle_devicelist(account->omemo,
                                from ? from : account_jid(account), items);

                        xmpp_stanza_t *children[2] = {NULL};
                        for (device = xmpp_stanza_get_children(list);
                             device; device = xmpp_stanza_get_next(device))
                        {
                            const char *name = xmpp_stanza_get_name(device);
                            if (weechat_strcasecmp(name, "device") != 0)
                                continue;

                            const char *device_id = xmpp_stanza_get_id(device);

                            char bundle_node[128] = {0};
                            snprintf(bundle_node, sizeof(bundle_node),
                                        "eu.siacs.conversations.axolotl.bundles:%s",
                                        device_id);

                            children[1] = NULL;
                            children[0] =
                            stanza__iq_pubsub_items(account->context, NULL,
                                                    strdup(bundle_node));
                            children[0] =
                            stanza__iq_pubsub(account->context, NULL, children,
                                                with_noop("http://jabber.org/protocol/pubsub"));
                            char *uuid = xmpp_uuid_gen(account->context);
                            children[0] =
                            stanza__iq(account->context, NULL, children, NULL, uuid,
                                to ? strdup(to) : NULL, from ? strdup(from) : NULL,
                                strdup("get"));
                            xmpp_free(account->context, uuid);

                            xmpp_send(conn, children[0]);
                            xmpp_stanza_release(children[0]);
                        }

                        if (weechat_strcasecmp(account_jid(account), from) == 0)
                        {
                            struct t_account_device *dev;
                            char id[64] = {0};

                            account__free_device_all(account);

                            dev = (t_account_device*)malloc(sizeof(struct t_account_device));

                            dev->id = account->omemo->device_id;
                            snprintf(id, sizeof(id), "%d", dev->id);
                            dev->name = strdup(id);
                            dev->label = strdup("weechat");
                            account__add_device(account, dev);

                            free(dev->label);
                            free(dev->name);
                            free(dev);

                            for (device = xmpp_stanza_get_children(list);
                                 device; device = xmpp_stanza_get_next(device))
                            {
                                const char *name = xmpp_stanza_get_name(device);
                                if (weechat_strcasecmp(name, "device") != 0)
                                    continue;

                                device_id = xmpp_stanza_get_id(device);

                                dev = (t_account_device*)malloc(sizeof(struct t_account_device));
                                dev->id = atoi(device_id);
                                dev->name = strdup(device_id);
                                dev->label = NULL;
                                account__add_device(account, dev);

                                free(dev->label);
                                free(dev->name);
                                free(dev);
                            }

                            reply = account__get_devicelist(account);
                            char *uuid = xmpp_uuid_gen(account->context);
                            xmpp_stanza_set_id(reply, uuid);
                            xmpp_free(account->context, uuid);
                            xmpp_stanza_set_attribute(reply, "to", from);
                            xmpp_stanza_set_attribute(reply, "from", to);
                            xmpp_send(conn, reply);
                            xmpp_stanza_release(reply);
                        }
                    }
                }
            }
            if (items_node
                && strncmp(items_node,
                           "eu.siacs.conversations.axolotl.bundles",
                           strnlen(items_node,
                                   strlen("eu.siacs.conversations.axolotl.bundles"))) == 0)
            {
                item = xmpp_stanza_get_child_by_name(items, "item");
                if (item)
                {
                    bundle = xmpp_stanza_get_child_by_name_and_ns(item, "bundle", "eu.siacs.conversations.axolotl");
                    if (bundle)
                    {
                        size_t node_prefix =
                            strlen("eu.siacs.conversations.axolotl.bundles:");
                        if (account->omemo && strlen(items_node) > node_prefix)
                        {
                            omemo__handle_bundle(account->omemo,
                                                 from ? from : account_jid(account),
                                                 strtol(items_node+node_prefix,
                                                        NULL, 10),
                                                 items);
                        }
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
                                struct t_channel *ptr_channel =
                                    channel__search(account, jid);
                                struct t_gui_buffer *ptr_buffer =
                                    ptr_channel ? ptr_channel->buffer : NULL;
                                if (ptr_buffer)
                                    weechat_buffer_set(ptr_buffer, "short_name", name);
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

    fin = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "fin", "urn:xmpp:mam:2");
    if (fin)
    {
        xmpp_stanza_t *set, *set__last;
        char *set__last__text;
        struct t_account_mam_query *mam_query;

        set = xmpp_stanza_get_child_by_name_and_ns(
            fin, "set", "http://jabber.org/protocol/rsm");
        mam_query = account__mam_query_search(account, id);
        if (set && mam_query)
        {
            struct t_channel *channel = channel__search(account,
                                                        mam_query->with);

            set__last = xmpp_stanza_get_child_by_name(set, "last");
            set__last__text = set__last
                ? xmpp_stanza_get_text(set__last) : NULL;

            if (channel && set__last__text)
            {
                channel__fetch_mam(account, channel, id,
                                   mam_query->has_start ? &mam_query->start : NULL,
                                   mam_query->has_end ? &mam_query->end : NULL,
                                   set__last__text);
            }
            else if (!set__last)
                account__mam_query_free(account, mam_query);
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
        account->disconnected = 0;

        xmpp_stanza_t *pres, *pres__c, *pres__status, *pres__status__text,
            *pres__x, *pres__x__text, **children;

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

        pgp__init(&account->pgp,
                  weechat_string_eval_expression(account_pgp_pubring_path(account),
                                                 NULL, NULL, NULL),
                  weechat_string_eval_expression(account_pgp_secring_path(account),
                                                 NULL, NULL, NULL));

        /* Send initial <presence/> so that we appear online to contacts */
        children = (xmpp_stanza_t**)malloc(sizeof(*children) * (3 + 1));

        pres__c = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(pres__c, "c");
        xmpp_stanza_set_ns(pres__c, "http://jabber.org/protocol/caps");
        xmpp_stanza_set_attribute(pres__c, "hash", "sha-1");
        xmpp_stanza_set_attribute(pres__c, "node", "http://weechat.org");

        xmpp_stanza_t *caps = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(caps, "caps");
        char *cap_hash;
        caps = connection__get_caps(caps, account, &cap_hash);
        xmpp_stanza_release(caps);
        xmpp_stanza_set_attribute(pres__c, "ver", cap_hash);
        free(cap_hash);

        children[0] = pres__c;

        pres__status = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(pres__status, "status");

        pres__status__text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(pres__status__text, account_status(account));
        xmpp_stanza_add_child(pres__status, pres__status__text);
        xmpp_stanza_release(pres__status__text);

        children[1] = pres__status;
        children[2] = NULL;

        if (account->pgp)
        {
            pres__x = xmpp_stanza_new(account->context);
            xmpp_stanza_set_name(pres__x, "x");
            xmpp_stanza_set_ns(pres__x, "jabber:x:signed");

            pres__x__text = xmpp_stanza_new(account->context);
            char *signature = pgp__sign(account->buffer, account->pgp, account_pgp_keyid(account), account_status(account));
            xmpp_stanza_set_text(pres__x__text, signature ? signature : "");
            free(signature);
            xmpp_stanza_add_child(pres__x, pres__x__text);
            xmpp_stanza_release(pres__x__text);

            children[2] = pres__x;
            children[3] = NULL;
        }

        pres = stanza__presence(account->context, NULL,
                                children, NULL, strdup(account_jid(account)),
                                NULL, NULL);
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);

        children[1] = NULL;
        children[0] =
            stanza__iq_enable(account->context, NULL, with_noop("urn:xmpp:carbons:2"));
        children[0] =
            stanza__iq(account->context, NULL, children,
                       strdup("jabber:client"), strdup("enable1"),
                       strdup(account_jid(account)), NULL, strdup("set"));

        xmpp_send(conn, children[0]);
        xmpp_stanza_release(children[0]);

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
        char *uuid = xmpp_uuid_gen(account->context);
        children[0] =
        stanza__iq(account->context, NULL, children, NULL, uuid,
                   strdup(account_jid(account)), strdup(account_jid(account)),
                   strdup("get"));
        xmpp_free(account->context, uuid);

        xmpp_send(conn, children[0]);
        xmpp_stanza_release(children[0]);

        omemo__init(account->buffer, &account->omemo, account->name);

        if (account->omemo)
        {
            children[0] =
            omemo__get_bundle(account->context,
                    strdup(account_jid(account)), NULL, account->omemo);
            xmpp_send(conn, children[0]);
            xmpp_stanza_release(children[0]);
        }

        (void) weechat_hook_signal_send("xmpp_account_connected",
                                        WEECHAT_HOOK_SIGNAL_STRING, account->name);
    }
    else
    {
        account__disconnect(account, 1);
      //xmpp_stop(account->context); //keep context?
    }
}

char* connection__rand_string(int length)
{
    char *string = (char*)malloc(length);
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
