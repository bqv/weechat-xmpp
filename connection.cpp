// This->Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdexcept>
#include <strophe.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <fmt/core.h>
#include <fmt/chrono.h>
#include <libxml/uri.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "xmpp/node.hh"
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

void weechat::connection::init()
{
    srand(time(NULL));
    libstrophe::initialize();
}

bool weechat::connection::version_handler(xmpp_stanza_t *stanza)
{
    const char *weechat_name = "weechat";
    std::unique_ptr<char> weechat_version(weechat_info_get("version", NULL));

    weechat_printf(NULL, "Received version request from %s", xmpp_stanza_get_from(stanza));

    auto reply = libstrophe::stanza::reply(stanza)
        .set_type("result");

    auto query = libstrophe::stanza(account.context)
        .set_name("query");
    if (const char *ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza)); ns) {
        query.set_ns(ns);
    }

    query.add_child(libstrophe::stanza(account.context)
                    .set_name("name")
                    .add_child(libstrophe::stanza(account.context)
                               .set_text(weechat_name)));
    query.add_child(libstrophe::stanza(account.context)
                    .set_name("version")
                    .add_child(libstrophe::stanza(account.context)
                               .set_text(weechat_version.get())));

    reply.add_child(query);

    account.connection.send(reply);

    return true;
}

bool weechat::connection::presence_handler(xmpp_stanza_t *stanza)
{
    weechat::user *user;
    weechat::channel *channel;

    auto binding = xml::presence(account.context, stanza);
    if (!binding.from)
        return 1;

    std::string clientid;
    if (auto caps = binding.capabilities())
    {
        auto node = caps->node;
        auto ver = caps->verification;

        clientid = fmt::format("{}#{}", node, ver);

        account.connection.send(stanza::iq()
                    .from(binding.to ? binding.to->full : "")
                    .to(binding.from
                        .transform([](auto& x) { return x.full; })
                        .value_or(std::string()))
                    .type("get")
                    .id(stanza::uuid(account.context))
                    .xep0030()
                    .query()
                    .build(account.context)
                    .get());
    }

    channel = account.channels.contains(binding.from->bare.data())
        ? &account.channels.find(binding.from->bare.data())->second : nullptr;
    if (!(binding.type && *binding.type == "unavailable") && !binding.muc_user() && !channel)
    {
        const char* jid = binding.from->bare.data();
        channel = &account.channels.emplace(
            std::make_pair(jid, weechat::channel {
                    account, weechat::channel::chat_type::MUC, jid, jid
                })).first->second;
    }

    if (binding.type && *binding.type == "error" && channel)
    {
        if (auto error = binding.error())
        {
            weechat_printf(channel->buffer, "[!]\t%s%sError: %s",
                           weechat_color("gray"),
                           binding.muc() ? "MUC " : "", error->reason());
        }
        return 1;
    }

    if (auto x = binding.muc_user())
    {
        for (int& status : x->statuses)
        {
            switch (status)
            {
                case 100: // Non-Anonymous: [message | Entering a room]: Inform user that any occupant is allowed to see the user's full JID
                    if (channel)
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
                    weechat_printf(channel->buffer, "[!]\t%sBanned from Room", weechat_color("gray"));
                    break;
                case 303: // : [presence | Exiting a room]: Inform all occupants of new room nickname
                    break;
                case 307: // : [presence | Removal from room]: Inform user that he or she has been kicked from the room
                    weechat_printf(channel->buffer, "[!]\t%sKicked from room", weechat_color("gray"));
                    break;
                case 321: // : [presence | Removal from room]: Inform user that he or she is being removed from the room because of an affiliation change
                    weechat_printf(channel->buffer, "[!]\t%sRoom Affiliation changed, kicked", weechat_color("gray"));
                    break;
                case 322: // : [presence | Removal from room]: Inform user that he or she is being removed from the room because the room has been changed to members-only and the user is not a member
                    weechat_printf(channel->buffer, "[!]\t%sRoom now members-only, kicked", weechat_color("gray"));
                    break;
                case 332: // : [presence | Removal from room]: Inform user that he or she is being removed from the room because of a system shutdown
                    weechat_printf(channel->buffer, "[!]\t%sRoom Shutdown", weechat_color("gray"));
                    break;
                default:
                    break;
            }
        }

        for (auto& item : x->items)
        {
            using xml::xep0045;

            std::string role(item.role ? xep0045::format_role(*item.role) : "");
            std::string affiliation(item.affiliation ? xep0045::format_affiliation(*item.affiliation) : "");
            std::string jid = item.target ? item.target->full : clientid;

            user = weechat::user::search(&account, binding.from->full.data());
            if (!user)
                user = new weechat::user(&account, binding.from->full.data(),
                                channel && binding.from->bare.data() == channel->id
                                 ? (binding.from->resource.size() ? binding.from->resource.data() : "")
                                 : binding.from->full.data());
            auto status = binding.status();
            auto show = binding.show();
            auto idle = binding.idle_since();
            user->profile.status_text = status ? strdup(status->data()) : NULL;
            user->profile.status = show ? strdup(show->data()) : NULL;
            user->profile.idle = idle ? fmt::format("{}", *idle) : std::string();
            user->is_away = show ? *show == "away" : false;
            user->profile.role = role.size() ? strdup(role.data()) : NULL;
            user->profile.affiliation = affiliation.size() && affiliation == "none"
                ? strdup(affiliation.data()) : NULL;
            if (channel)
            {
                if (auto signature = binding.signature())
                {
                    user->profile.pgp_id = account.pgp.verify(channel->buffer, signature->data());
                    if (channel->type != weechat::channel::chat_type::MUC)
                        channel->pgp.ids.emplace(user->profile.pgp_id);
                }

                if (weechat_strcasecmp(role.data(), "none") == 0)
                    channel->remove_member(binding.from->full.data(), status ? status->data() : nullptr);
                else
                    channel->add_member(binding.from->full.data(), jid.data());
            }
        }
    }
    else
    {
        user = user::search(&account, binding.from->full.data());
        if (!user)
            user = new weechat::user(&account, binding.from->full.data(),
                                     channel && binding.from->bare.data() == channel->id
                                     ? (binding.from->resource.size() ? binding.from->resource.data() : "")
                                     : binding.from->full.data());
        auto status = binding.status();
        auto show = binding.show();
        auto idle = binding.idle_since();
        user->profile.status_text = status ? strdup(status->data()) : NULL;
        user->profile.status = show ? strdup(show->data()) : NULL;
        user->profile.idle = idle ? fmt::format("{}", *idle) : std::string();
        user->is_away = show ? *show == "away" : false;
        user->profile.role = NULL;
        user->profile.affiliation = NULL;
        if (channel)
        {
            if (auto signature = binding.signature(); signature)
            {
                user->profile.pgp_id = account.pgp.verify(channel->buffer, signature->data());
                if (channel->type != weechat::channel::chat_type::MUC)
                    channel->pgp.ids.emplace(user->profile.pgp_id);
            }

            if (user->profile.role)
                channel->remove_member(binding.from->full.data(), status ? status->data() : nullptr);
            else
                channel->add_member(binding.from->full.data(), clientid.data());
        }
    }

    return true;
}

bool weechat::connection::message_handler(xmpp_stanza_t *stanza)
{
    weechat::channel *channel, *parent_channel;
    xmpp_stanza_t *x, *body, *delay, *topic, *replace, *request, *markable, *composing, *sent, *received, *result, *forwarded, *event, *items, *item, *list, *device, *encrypted;
    const char *type, *from, *nick, *from_bare, *to, *to_bare, *id, *thread, *replace_id, *timestamp;
    char *text, *intext, *difftext = NULL, *cleartext = NULL;
    struct tm time = {0};
    time_t date = 0;

    auto binding = xml::message(account.context, stanza);
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
            from_bare = xmpp_jid_bare(account.context, from);
            from = xmpp_jid_resource(account.context, from);
            channel = account.channels.contains(from_bare)
                ? &account.channels.find(from_bare)->second : nullptr;
            if (!channel)
            {
                if (weechat_strcasecmp(type, "groupchat") == 0)
                    channel = new weechat::channel(account, weechat::channel::chat_type::MUC, from_bare, from_bare);
                else
                    channel = new weechat::channel(account, weechat::channel::chat_type::PM, from_bare, from_bare);
            }
            channel->update_topic(intext ? intext : "", from, 0);
            if (intext != NULL)
                xmpp_free(account.context, intext);
        }

        composing = xmpp_stanza_get_child_by_name_and_ns(
            stanza, "composing", "http://jabber.org/protocol/chatstates");
        if (composing != NULL)
        {
            from = xmpp_stanza_get_from(stanza);
            if (from == NULL)
                return 1;
            from_bare = xmpp_jid_bare(account.context, from);
            nick = xmpp_jid_resource(account.context, from);
            channel = account.channels.contains(from_bare)
                ? &account.channels.find(from_bare)->second : nullptr;
            if (!channel)
                return 1;
            auto user = user::search(&account, from);
            if (!user)
                user = new weechat::user(&account, from,
                                         weechat_strcasecmp(from_bare, channel->id.data()) == 0
                                         ? nick : from);
            channel->add_typing(user);
            weechat_printf(channel->buffer, "...\t%s%s typing",
                           weechat_color("gray"),
                           channel->type == weechat::channel::chat_type::MUC ? nick : from);
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
            return message_handler(message);
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
                    int ret = message_handler(message);
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
                            if (account.omemo)
                            {
                                account.omemo.handle_devicelist(
                                    from ? from : account.jid().data(), items);
                            }

                            auto children = std::unique_ptr<xmpp_stanza_t*[]>(new xmpp_stanza_t*[3 + 1]);

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
                                stanza__iq_pubsub_items(account.context, NULL,
                                                        strdup(bundle_node));
                                children[0] =
                                stanza__iq_pubsub(account.context, NULL, children.get(),
                                                  with_noop("http://jabber.org/protocol/pubsub"));
                                char *uuid = xmpp_uuid_gen(account.context);
                                children[0] =
                                stanza__iq(account.context, NULL, children.get(), NULL, uuid,
                                            strdup(to), strdup(from), strdup("get"));
                                xmpp_free(account.context, uuid);

                                account.connection.send(children[0]);
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
    from_bare = xmpp_jid_bare(account.context, from);
    to = xmpp_stanza_get_to(stanza);
    if (to == NULL)
        to = account.jid().data();
    to_bare = to ? xmpp_jid_bare(account.context, to) : NULL;
    id = xmpp_stanza_get_id(stanza);
    thread = xmpp_stanza_get_attribute(stanza, "thread");
    replace = xmpp_stanza_get_child_by_name_and_ns(stanza, "replace",
                                                   "urn:xmpp:message-correct:0");
    replace_id = replace ? xmpp_stanza_get_id(replace) : NULL;
    request = xmpp_stanza_get_child_by_name_and_ns(stanza, "request",
                                                   "urn:xmpp:receipts");
    markable = xmpp_stanza_get_child_by_name_and_ns(stanza, "markable",
                                                    "urn:xmpp:chat-markers:0");

    const char *channel_id = account.jid() == from_bare ? to_bare : from_bare;
    parent_channel = account.channels.contains(channel_id)
        ? &account.channels.find(channel_id)->second : nullptr;
    const char *pm_id = account.jid() == from_bare ? to : from;
    channel = parent_channel;
    if (!channel)
        channel = new weechat::channel(account,
                               weechat_strcasecmp(type, "groupchat") == 0
                               ? weechat::channel::chat_type::MUC : weechat::channel::chat_type::PM,
                               channel_id, channel_id);
    if (channel && channel->type == weechat::channel::chat_type::MUC
        && weechat_strcasecmp(type, "chat") == 0)
        channel = new weechat::channel(account, weechat::channel::chat_type::PM,
                               pm_id, pm_id);

    if (id && (markable || request))
    {
        auto unread = new weechat::channel::unread();
        unread->id = strdup(id);
        unread->thread = thread ? strdup(thread) : NULL;

        xmpp_stanza_t *message = xmpp_message_new(account.context, NULL,
                                                  channel->id.data(), NULL);

        if (request)
        {
            xmpp_stanza_t *message__received = xmpp_stanza_new(account.context);
            xmpp_stanza_set_name(message__received, "received");
            xmpp_stanza_set_ns(message__received, "urn:xmpp:receipts");
            xmpp_stanza_set_id(message__received, unread->id);

            xmpp_stanza_add_child(message, message__received);
            xmpp_stanza_release(message__received);
        }

        if (markable)
        {
            xmpp_stanza_t *message__received = xmpp_stanza_new(account.context);
            xmpp_stanza_set_name(message__received, "received");
            xmpp_stanza_set_ns(message__received, "urn:xmpp:chat-markers:0");
            xmpp_stanza_set_id(message__received, unread->id);

            xmpp_stanza_add_child(message, message__received);
            xmpp_stanza_release(message__received);
        }

        if (unread->thread)
        {
            xmpp_stanza_t *message__thread = xmpp_stanza_new(account.context);
            xmpp_stanza_set_name(message__thread, "thread");

            xmpp_stanza_t *message__thread__text = xmpp_stanza_new(account.context);
            xmpp_stanza_set_text(message__thread__text, unread->thread);
            xmpp_stanza_add_child(message__thread, message__thread__text);
            xmpp_stanza_release(message__thread__text);

            xmpp_stanza_add_child(message, message__thread);
            xmpp_stanza_release(message__thread);
        }

        xmpp_send(account.connection, message);
        xmpp_stanza_release(message);

        channel->unreads.push_back(*unread);
    }

    encrypted = xmpp_stanza_get_child_by_name_and_ns(stanza, "encrypted",
                                                     "eu.siacs.conversations.axolotl");
    x = xmpp_stanza_get_child_by_name_and_ns(stanza, "x", "jabber:x:encrypted");
    intext = xmpp_stanza_get_text(body);
    if (encrypted && account.omemo)
    {
        cleartext = account.omemo.decode(&account, from_bare, encrypted);
        if (!cleartext)
        {
            weechat_printf_date_tags(channel->buffer, 0, "notify_none", "%s%s (%s)",
                                     weechat_prefix("error"), "OMEMO Decryption Error", from);
            return 1;
        }
    }
    if (x)
    {
        char *ciphertext = xmpp_stanza_get_text(x);
        cleartext = account.pgp.decrypt(channel->buffer, ciphertext);
        xmpp_free(account.context, ciphertext);
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
                    char str_tag[24] = {0};
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
                int retention = 0;
                int modification = 0;

                for (size_t i = 0; i < result.sessz; i++)
                    switch (result.ses[i].type)
                    {
                        case DIFF_ADD:
                            weechat_string_dyn_concat(visual, weechat_color("green"), -1);
                            *ch = *(const char *)result.ses[i].e;
                            weechat_string_dyn_concat(visual, ch, -1);
                            modification++;
                            break;
                        case DIFF_DELETE:
                            weechat_string_dyn_concat(visual, weechat_color("red"), -1);
                            *ch = *(const char *)result.ses[i].e;
                            weechat_string_dyn_concat(visual, ch, -1);
                            modification++;
                            break;
                        case DIFF_COMMON:
                        default:
                            weechat_string_dyn_concat(visual, weechat_color("resetcolor"), -1);
                            *ch = *(const char *)result.ses[i].e;

                            weechat_string_dyn_concat(visual, ch, -1);
                            retention++;
                            break;
                    }
                free(result.ses);
                free(result.lcs);

                if ((modification > 20) && (modification > retention)) {
                    weechat_string_dyn_free(visual, 1);
                    visual = weechat_string_dyn_alloc(256);
                    weechat_string_dyn_concat(visual, weechat_color("red"), -1);
                    if (strlen(orig) >= 16) {
                        weechat_string_dyn_concat(visual, orig, 16);
                        weechat_string_dyn_concat(visual, "...", -1);
                    } else
                        weechat_string_dyn_concat(visual, orig, -1);
                    weechat_string_dyn_concat(visual, weechat_color("green"), -1);
                    weechat_string_dyn_concat(visual, text, -1);
                }
                difftext = strdup(*visual);
                weechat_string_dyn_free(visual, 1);
            }
        }
    }

    nick = from;
    if (weechat_strcasecmp(type, "groupchat") == 0)
    {
        nick = channel->name == xmpp_jid_bare(account.context, from)
            ? xmpp_jid_resource(account.context, from)
            : from;
    }
    else if (parent_channel && parent_channel->type == weechat::channel::chat_type::MUC)
    {
        nick = channel->name == from
            ? xmpp_jid_resource(account.context, from)
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

    if (channel->type == weechat::channel::chat_type::PM)
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
    else if (channel->type == weechat::channel::chat_type::PM
             && from_bare != account.jid())
        weechat_string_dyn_concat(dyn_tags, ",notify_private", -1);
    else
        weechat_string_dyn_concat(dyn_tags, ",notify_message,log1", -1);

    const char *edit = replace ? "* " : ""; // Losing which message was edited, sadly
    if (x && text == cleartext && channel->transport != weechat::channel::transport::PGP)
    {
        channel->transport = weechat::channel::transport::PGP;
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s%sTransport: %s",
                                 weechat_prefix("network"), weechat_color("gray"),
                                 channel::transport_name(channel->transport));
    }
    else if (!x && text == intext && channel->transport != weechat::channel::transport::PLAIN)
    {
        channel->transport = weechat::channel::transport::PLAIN;
        weechat_printf_date_tags(channel->buffer, date, NULL, "%s%sTransport: %s",
                                 weechat_prefix("network"), weechat_color("gray"),
                                 channel::transport_name(channel->transport));
    }
    if (channel_id == from_bare && to == channel->id)
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t[to %s]: %s",
                                 edit, user::as_prefix_raw(&account, nick).data(),
                                 to, difftext ? difftext : text ? text : "");
    else if (weechat_string_match(text, "/me *", 0))
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t%s %s",
                                 edit, weechat_prefix("action"), user::as_prefix_raw(&account, nick).data(),
                                 difftext ? difftext+4 : text ? text+4 : "");
    else
        weechat_printf_date_tags(channel->buffer, date, *dyn_tags, "%s%s\t%s",
                                 edit, user::as_prefix_raw(&account, nick).data(),
                                 difftext ? difftext : text ? text : "");

    weechat_string_dyn_free(dyn_tags, 1);

    if (intext)
        xmpp_free(account.context, intext);
    if (difftext)
        free(difftext);
    if (cleartext)
        free(cleartext);

    return true;
}

xmpp_stanza_t *weechat::connection::get_caps(xmpp_stanza_t *reply, char **hash)
{
    xmpp_stanza_t *query = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(query, "query");
    xmpp_stanza_set_ns(query, "http://jabber.org/protocol/disco#info");

    char *client_name = weechat_string_eval_expression(
            "weechat ${info:version}", NULL, NULL, NULL);
    char **serial = weechat_string_dyn_alloc(256);
    weechat_string_dyn_concat(serial, "client/pc//", -1);
    weechat_string_dyn_concat(serial, client_name, -1);
    weechat_string_dyn_concat(serial, "<", -1);

    xmpp_stanza_t *identity = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(identity, "identity");
    xmpp_stanza_set_attribute(identity, "category", "client");
    xmpp_stanza_set_attribute(identity, "name", client_name);
    free(client_name);
    xmpp_stanza_set_attribute(identity, "type", "pc");
    xmpp_stanza_add_child(query, identity);
    xmpp_stanza_release(identity);

    xmpp_stanza_t *feature = NULL;

#define FEATURE(NS)                                 \
    feature = xmpp_stanza_new(account.context);     \
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

    xmpp_stanza_t *x = xmpp_stanza_new(account.context);
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
    // This->is utter bullshit, TODO: anything but this->
#define FEATURE1(VAR, TYPE, VALUE)                            \
    field = xmpp_stanza_new(account.context);                 \
    xmpp_stanza_set_name(field, "field");                     \
    xmpp_stanza_set_attribute(field, "var", VAR);             \
    if(TYPE) xmpp_stanza_set_attribute(field, "type", TYPE);  \
    value = xmpp_stanza_new(account.context);                 \
    xmpp_stanza_set_name(value, "value");                     \
    text = xmpp_stanza_new(account.context);                  \
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
    field = xmpp_stanza_new(account.context);                 \
    xmpp_stanza_set_name(field, "field");                     \
    xmpp_stanza_set_attribute(field, "var", VAR);             \
    xmpp_stanza_set_attribute(field, "type", TYPE);           \
    value = xmpp_stanza_new(account.context);                 \
    xmpp_stanza_set_name(value, "value");                     \
    text = xmpp_stanza_new(account.context);                  \
    xmpp_stanza_set_text(text, VALUE1);                       \
    xmpp_stanza_add_child(value, text);                       \
    xmpp_stanza_release(text);                                \
    xmpp_stanza_add_child(field, value);                      \
    xmpp_stanza_release(value);                               \
    value = xmpp_stanza_new(account.context);                 \
    xmpp_stanza_set_name(value, "value");                     \
    text = xmpp_stanza_new(account.context);                  \
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
    xmpp_sha1_t *sha1 = xmpp_sha1_new(account.context);
    xmpp_sha1_update(sha1, (unsigned char*)*serial, strlen(*serial));
    xmpp_sha1_final(sha1);
    weechat_string_dyn_free(serial, 1);
    xmpp_sha1_to_digest(sha1, digest);
    xmpp_sha1_free(sha1);

    if (hash)
    {
        char *cap_hash = xmpp_base64_encode(account.context, digest, 20);
        *hash = strdup(cap_hash);
        xmpp_free(account.context, cap_hash);
    }

    return reply;
}

bool weechat::connection::iq_handler(xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *reply, *query, *text, *fin;
    xmpp_stanza_t         *pubsub, *items, *item, *list, *bundle, *device;
    xmpp_stanza_t         *storage, *conference, *nick;

    auto binding = xml::iq(account.context, stanza);
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
            reply = get_caps(xmpp_stanza_reply(stanza), NULL);

            account.connection.send(reply);
            xmpp_stanza_release(reply);
        }

        if (weechat_strcasecmp(type, "result") == 0)
        {
            xmpp_stanza_t *identity = xmpp_stanza_get_child_by_name(query, "identity");

            if (identity)
            {
                std::string category;
                std::string name;
                std::string type;

                if (const char *attr = xmpp_stanza_get_attribute(identity, "category"))
                    category = attr;
                if (const char *attr = xmpp_stanza_get_attribute(identity, "name"))
                    name = unescape(attr);
                if (const char *attr = xmpp_stanza_get_attribute(identity, "type"))
                    type = attr;

                if (category == "conference")
                {
                    auto ptr_channel = account.channels.find(from);
                    if (ptr_channel != account.channels.end())
                        ptr_channel->second.update_name(name.data());
                }
                else if (category == "conference")
                {
                    xmpp_stanza_t *children[2] = {NULL};
                    children[0] = stanza__iq_pubsub_items(account.context, NULL,
                            const_cast<char*>("eu.siacs.conversations.axolotl.devicelist"));
                    children[0] = stanza__iq_pubsub(account.context, NULL,
                            children, with_noop("http://jabber.org/protocol/pubsub"));
                    children[0] = stanza__iq(account.context, NULL, children, NULL,
                            strdup("fetch2"), to ? strdup(to) : NULL,
                            binding.from ? strdup(binding.from->bare.data()) : NULL, strdup("get"));
                    account.connection.send(children[0]);
                    xmpp_stanza_release(children[0]);
                }
            }
        }
    }
    query = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "query", "jabber:iq:private");
    if (query && type)
    {
        storage = xmpp_stanza_get_child_by_name_and_ns(
                query, "storage", "storage:bookmarks");
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

                account.connection.send(stanza::iq()
                            .from(to)
                            .to(jid)
                            .type("get")
                            .id(stanza::uuid(account.context))
                            .xep0030()
                            .query()
                            .build(account.context)
                            .get());
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
                    weechat_command(account.buffer, *command);
                    auto ptr_channel = account.channels.find(jid);
                    struct t_gui_buffer *ptr_buffer =
                        ptr_channel != account.channels.end()
                        ? ptr_channel->second.buffer : NULL;
                    if (ptr_buffer)
                        weechat_buffer_set(ptr_buffer, "short_name", name);
                    weechat_string_dyn_free(command, 1);
                }

                if (nick)
                    free(intext);
            }
        }
    }

    pubsub = xmpp_stanza_get_child_by_name_and_ns(
        stanza, "pubsub", "http://jabber.org/protocol/pubsub");
    if (pubsub)
    {
        const char *items_node, *device_id;

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
                    const char *item_id = xmpp_stanza_get_id(item);
                    list = xmpp_stanza_get_child_by_name_and_ns(
                        item, "list", "eu.siacs.conversations.axolotl");
                    if (list && account.omemo)
                    {
                        account.omemo.handle_devicelist(
                            from ? from : account.jid().data(), items);

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
                            stanza__iq_pubsub_items(account.context, NULL,
                                                    strdup(bundle_node));
                            children[0] =
                            stanza__iq_pubsub(account.context, NULL, children,
                                                with_noop("http://jabber.org/protocol/pubsub"));
                            char *uuid = xmpp_uuid_gen(account.context);
                            children[0] =
                            stanza__iq(account.context, NULL, children, NULL, uuid,
                                to ? strdup(to) : NULL, from ? strdup(from) : NULL,
                                strdup("get"));
                            xmpp_free(account.context, uuid);

                            account.connection.send(children[0]);
                            xmpp_stanza_release(children[0]);
                        }

                        if (account.jid() == from)
                        {
                            weechat::account::device dev;
                            char id[64] = {0};

                            account.devices.clear();

                            dev.id = account.omemo.device_id;
                            snprintf(id, sizeof(id), "%d", dev.id);
                            dev.name = id;
                            dev.label = "weechat";
                            account.devices.emplace(dev.id, dev);

                            for (device = xmpp_stanza_get_children(list);
                                 device; device = xmpp_stanza_get_next(device))
                            {
                                const char *name = xmpp_stanza_get_name(device);
                                if (weechat_strcasecmp(name, "device") != 0)
                                    continue;

                                device_id = xmpp_stanza_get_id(device);

                                dev.id = atoi(device_id);
                                dev.name = device_id;
                                dev.label = "";
                                account.devices.emplace(dev.id, dev);
                            }

                            reply = account.get_devicelist();
                            char *uuid = xmpp_uuid_gen(account.context);
                            xmpp_stanza_set_id(reply, uuid);
                            xmpp_free(account.context, uuid);
                            xmpp_stanza_set_attribute(reply, "to", from);
                            xmpp_stanza_set_attribute(reply, "from", to);
                            account.connection.send(reply);
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
                        if (account.omemo && strlen(items_node) > node_prefix)
                        {
                            account.omemo.handle_bundle(
                                from ? from : account.jid().data(),
                                                 strtol(items_node+node_prefix,
                                                        NULL, 10),
                                                 items);
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
        weechat::account::mam_query mam_query;

        set = xmpp_stanza_get_child_by_name_and_ns(
            fin, "set", "http://jabber.org/protocol/rsm");
        if (set && account.mam_query_search(&mam_query, id))
        {
            auto channel = account.channels.find(mam_query.with.data());

            set__last = xmpp_stanza_get_child_by_name(set, "last");
            set__last__text = set__last
                ? xmpp_stanza_get_text(set__last) : NULL;

            if (channel != account.channels.end() && set__last__text)
            {
                channel->second.fetch_mam(id,
                                   *mam_query.start.map([](time_t& t){ return &t; }).disjunction(nullptr),
                                   *mam_query.end.map([](time_t& t){ return &t; }).disjunction(nullptr),
                                   set__last__text);
            }
            else if (!set__last)
                account.mam_query_remove(mam_query.id);
        }
    }

    return true;
}

bool weechat::connection::conn_handler(event status, int error, xmpp_stream_error_t *stream_error)
{
    (void)error;
    (void)stream_error;

    if (status == event::connect)
    {
        account.disconnected = 0;

        xmpp_stanza_t *pres__c, *pres__status, *pres__status__text,
            *pres__x, *pres__x__text;

        this->handler_add<jabber::iq::version>(
            "iq", nullptr, [](xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata) {
                auto& connection = *reinterpret_cast<weechat::connection*>(userdata);
                if (connection != conn) throw std::invalid_argument("connection != conn");
                return connection.version_handler(stanza) ? 1 : 0;
            });
        this->handler_add(
            "presence", nullptr, [](xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata) {
                auto& connection = *reinterpret_cast<weechat::connection*>(userdata);
                if (connection != conn) throw std::invalid_argument("connection != conn");
                return connection.presence_handler(stanza) ? 1 : 0;
            });
        this->handler_add(
            "message", /*type*/ nullptr, [](xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata) {
                auto& connection = *reinterpret_cast<weechat::connection*>(userdata);
                if (connection != conn) throw std::invalid_argument("connection != conn");
                return connection.message_handler(stanza) ? 1 : 0;
            });
        this->handler_add(
            "iq", nullptr, [](xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata) {
                auto& connection = *reinterpret_cast<weechat::connection*>(userdata);
                if (connection != conn) throw std::invalid_argument("connection != conn");
                return connection.iq_handler(stanza) ? 1 : 0;
            });

        /* Send initial <presence/> so that we appear online to contacts */
        auto children = std::unique_ptr<xmpp_stanza_t*[]>(new xmpp_stanza_t*[3 + 1]);

        pres__c = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(pres__c, "c");
        xmpp_stanza_set_ns(pres__c, "http://jabber.org/protocol/caps");
        xmpp_stanza_set_attribute(pres__c, "hash", "sha-1");
        xmpp_stanza_set_attribute(pres__c, "node", "http://weechat.org");

        xmpp_stanza_t *caps = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(caps, "caps");
        char *cap_hash;
        caps = this->get_caps(caps, &cap_hash);
        xmpp_stanza_release(caps);
        xmpp_stanza_set_attribute(pres__c, "ver", cap_hash);
        free(cap_hash);

        children[0] = pres__c;

        pres__status = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(pres__status, "status");

        pres__status__text = xmpp_stanza_new(account.context);
        xmpp_stanza_set_text(pres__status__text, account.status().data());
        xmpp_stanza_add_child(pres__status, pres__status__text);
        xmpp_stanza_release(pres__status__text);

        children[1] = pres__status;
        children[2] = NULL;

        if (true)//account.pgp)
        {
            pres__x = xmpp_stanza_new(account.context);
            xmpp_stanza_set_name(pres__x, "x");
            xmpp_stanza_set_ns(pres__x, "jabber:x:signed");

            pres__x__text = xmpp_stanza_new(account.context);
            char *signature = account.pgp.sign(account.buffer, account.pgp_keyid().data(), account.status().data());
            xmpp_stanza_set_text(pres__x__text, signature ? signature : "");
            free(signature);
            xmpp_stanza_add_child(pres__x, pres__x__text);
            xmpp_stanza_release(pres__x__text);

            children[2] = pres__x;
            children[3] = NULL;
        }

        this->send(stanza::presence()
                    .from(account.jid())
                    .build(account.context)
                    .get());

        this->send(stanza::iq()
                    .from(account.jid())
                    .type("set")
                    .id(stanza::uuid(account.context))
                    .xep0280()
                    .enable()
                    .build(account.context)
                    .get());

        this->send(stanza::iq()
                    .from(account.jid())
                    .to(account.jid())
                    .type("get")
                    .id(stanza::uuid(account.context))
                    .rfc6121()
                    .query(stanza::rfc6121::query())
                    .build(account.context)
                    .get());

        this->send(stanza::iq()
                    .from(account.jid())
                    .to(account.jid())
                    .type("get")
                    .id(stanza::uuid(account.context))
                    .xep0049()
                    .query(stanza::xep0049::query().bookmarks())
                    .build(account.context)
                    .get());

        children[1] = NULL;
        children[0] =
        stanza__iq_pubsub_items(account.context, NULL,
                                strdup("eu.siacs.conversations.axolotl.devicelist"));
        children[0] =
        stanza__iq_pubsub(account.context, NULL, children.get(),
                          with_noop("http://jabber.org/protocol/pubsub"));
        char *uuid = xmpp_uuid_gen(account.context);
        children[0] =
        stanza__iq(account.context, NULL, children.get(), NULL, uuid,
                   strdup(account.jid().data()), strdup(account.jid().data()),
                   strdup("get"));
        xmpp_free(account.context, uuid);

        this->send(children[0]);
        xmpp_stanza_release(children[0]);

        account.omemo.init(account.buffer, account.name.data());

        if (account.omemo)
        {
            children[0] =
            account.omemo.get_bundle(account.context,
                                      strdup(account.jid().data()), NULL);
            this->send(children[0]);
            xmpp_stanza_release(children[0]);
        }

        (void) weechat_hook_signal_send("xmpp_account_connected",
                                        WEECHAT_HOOK_SIGNAL_STRING, account.name.data());
    }
    else
    {
        account.disconnect(1);
      //xmpp_stop(account.context); //keep context?
    }

    return true;
}

char* rand_string(int length)
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

int weechat::connection::connect(std::string jid, std::string password, weechat::tls_policy tls)
{
    static const unsigned ka_timeout_sec = 60;
    static const unsigned ka_timeout_ivl = 1;

    m_conn.set_keepalive(ka_timeout_sec, ka_timeout_ivl);

    const char *resource = account.resource().data();
    if (!(resource && strlen(resource)))
    {
        char *const rand = rand_string(8);
        char ident[64] = {0};
        snprintf(ident, sizeof(ident), "weechat.%s", rand);
        free(rand);

        account.resource(ident);
        resource = account.resource().data();
    }
    m_conn.set_jid(xmpp_jid_new(account.context,
                                xmpp_jid_node(account.context, jid.data()),
                                xmpp_jid_domain(account.context, jid.data()),
                                resource));
    m_conn.set_pass(password.data());

    int flags = m_conn.get_flags();
    switch (tls)
    {
        case weechat::tls_policy::disable:
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
            break;
        case weechat::tls_policy::normal:
            flags &= ~XMPP_CONN_FLAG_DISABLE_TLS;
            flags &= ~XMPP_CONN_FLAG_TRUST_TLS;
            break;
        case weechat::tls_policy::trust:
            flags |= XMPP_CONN_FLAG_TRUST_TLS;
            break;
        default:
            break;
    }
    m_conn.set_flags(flags);

    if (!connect_client(
            nullptr, 0, [](xmpp_conn_t *conn, xmpp_conn_event_t status,
                           int error, xmpp_stream_error_t *stream_error,
                           void *userdata) {
                auto& connection = *reinterpret_cast<weechat::connection*>(userdata);
                if (connection != conn) throw std::invalid_argument("connection != conn");
                connection.conn_handler(static_cast<event>(status), error, stream_error);
            }))
    {
        weechat_printf(
            nullptr,
            _("%s%s: error connecting to %s"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            jid.data());
        return false;
    }

    return true;
}

void weechat::connection::process(xmpp_ctx_t *context, const unsigned long timeout)
{
    xmpp_run_once(context ? context : this->context(), timeout);
}
