// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <regex>
#include <fmt/core.h>
#include <optional>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "account.hh"
#include "omemo.hh"
#include "user.hh"
#include "channel.hh"
#include "input.hh"
#include "buffer.hh"
#include "pgp.hh"
#include "util.hh"
#include "xmpp/node.hh"

void weechat::channel::set_transport(enum weechat::channel::transport transport, int force)
{
    if (force)
        switch (transport)
        {
            case weechat::channel::transport::PLAIN:
                omemo.enabled = 0;
                pgp.enabled = 0;
                break;
            case weechat::channel::transport::OMEMO:
                omemo.enabled = 1;
                pgp.enabled = 0;
                break;
            case weechat::channel::transport::PGP:
                omemo.enabled = 0;
                pgp.enabled = 1;
                break;
            default:
                break;
        }

    if (this->transport != transport)
    {
        this->transport = transport;
        weechat_printf_date_tags(buffer, 0, NULL, "%s%sTransport: %s",
                                 weechat_prefix("network"), weechat_color("gray"),
                                 weechat::channel::transport_name(this->transport));
    }
}

struct t_gui_buffer *weechat::channel::search_buffer(weechat::channel::chat_type type,
                                                     const char *name)
{
    struct t_hdata *hdata_buffer;
    struct t_gui_buffer *ptr_buffer;
    const char *ptr_type, *ptr_account_name, *ptr_remote_jid;

    hdata_buffer = weechat_hdata_get("buffer");
    ptr_buffer = (struct t_gui_buffer*)weechat_hdata_get_list(hdata_buffer, "gui_buffers");

    while (ptr_buffer)
    {
        if (weechat_buffer_get_pointer(ptr_buffer, "plugin") == weechat_plugin)
        {
            ptr_type = weechat_buffer_get_string(ptr_buffer, "localvar_type");
            ptr_account_name = weechat_buffer_get_string(ptr_buffer,
                                                           "localvar_account");
            ptr_remote_jid = weechat_buffer_get_string(ptr_buffer,
                                                         "localvar_remote_jid");
            if (ptr_type && ptr_type[0]
                && ptr_account_name && ptr_account_name[0]
                && ptr_remote_jid && ptr_remote_jid[0]
                && (   ((  (type == weechat::channel::chat_type::MUC))
                        && (strcmp(ptr_type, "room") == 0))
                    || ((  (type == weechat::channel::chat_type::PM))
                        && (strcmp(ptr_type, "private") == 0)))
                && (ptr_account_name == account.name)
                && (weechat_strcasecmp(ptr_remote_jid, name) == 0))
            {
                return ptr_buffer;
            }
        }
        ptr_buffer = (struct t_gui_buffer*)weechat_hdata_move(hdata_buffer, ptr_buffer, 1);
    }

    return NULL;
}

struct t_gui_buffer *weechat::channel::create_buffer(weechat::channel::chat_type type,
                                                     const char *name)
{
    struct t_gui_buffer *ptr_buffer;
    int buffer_created;
    const char *short_name = NULL, *localvar_remote_jid = NULL;

    buffer_created = 0;

    std::string buffer_name = fmt::format("{}.{}", account.name, name);

    ptr_buffer = weechat::channel::search_buffer(type, name);
    if (ptr_buffer)
    {
        weechat_nicklist_remove_all(ptr_buffer);
    }
    else
    {
        ptr_buffer = weechat_buffer_new(buffer_name.data(),
                                        &input__data_cb, NULL, NULL,
                                        &buffer__close_cb, NULL, NULL);
        if (!ptr_buffer)
            return NULL;

        buffer_created = 1;
    }

    if (buffer_created)
    {
        char *res = (char*)strrchr(name, '/');
        if (!weechat_buffer_get_integer(ptr_buffer, "short_name_is_set"))
            weechat_buffer_set(ptr_buffer, "short_name",
                               res ? res + 1 : name);
    }
    else
    {
        short_name = weechat_buffer_get_string(ptr_buffer, "short_name");
        localvar_remote_jid = weechat_buffer_get_string(ptr_buffer,
                                                     "localvar_remote_jid");

        if (!short_name ||
            (localvar_remote_jid && (strcmp(localvar_remote_jid, short_name) == 0)))
        {
            weechat_buffer_set(ptr_buffer, "short_name",
                               xmpp_jid_node(account.context, name));
        }
    }
    if(!(account.nickname().size()))
        account.nickname(xmpp_jid_node(account.context, account.jid().data()));

    // Set notify level for buffer: "0" = never add to hotlist
    //                              "1" = add for highlights only
    //                              "2" = add for highlights and messages
    //                              "3" = add for all messages.
    weechat_buffer_set(ptr_buffer, "notify",
                       (type == weechat::channel::chat_type::PM) ? "3" : "2");
    weechat_buffer_set(ptr_buffer, "localvar_set_type",
                       (type == weechat::channel::chat_type::PM) ? "private" : "channel");
    weechat_buffer_set(ptr_buffer, "localvar_set_nick",
                       account.nickname().data());
    weechat_buffer_set(ptr_buffer, "localvar_set_account", account.name.data());
    weechat_buffer_set(ptr_buffer, "localvar_set_remote_jid", name);
    weechat_buffer_set(ptr_buffer, "input_multiline", "1");

    if (buffer_created)
    {
        (void) weechat_hook_signal_send("logger_backlog",
                                        WEECHAT_HOOK_SIGNAL_POINTER,
                                        ptr_buffer);
        weechat_buffer_set(ptr_buffer, "input_get_unknown_commands", "1");
        if (type != weechat::channel::chat_type::PM)
        {
            weechat_buffer_set(ptr_buffer, "nicklist", "1");
            weechat_buffer_set(ptr_buffer, "nicklist_display_groups", "0");
            weechat_buffer_set_pointer(ptr_buffer, "nicklist_callback",
                                       (void*)&buffer__nickcmp_cb);
            weechat_buffer_set_pointer(ptr_buffer, "nicklist_callback_pointer",
                                       &account);
        }

        weechat_buffer_set(ptr_buffer, "highlight_words_add",
                           account.nickname().data());
        weechat_buffer_set(ptr_buffer, "highlight_tags_restrict",
                           "message");
    }

    return ptr_buffer;
}

void weechat::channel::add_nicklist_groups()
{
    if (type == weechat::channel::chat_type::PM)
        return;

    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 000, "~").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 001, "&").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 002, "@").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 003, "%").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 004, "+").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 005, "?").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 006, "!").data(),
                               "weechat.color.nicklist_group", 1);
    weechat_nicklist_add_group(buffer, NULL, fmt::format("%03d|%s", 999, "...").data(),
                               "weechat.color.nicklist_group", 1);
}

weechat::channel::channel(weechat::account& account,
                          weechat::channel::chat_type type,
                          const char *id, const char *name) : id(id), name(name), type(type), account(account)
{
    if (!id || !name || !name[0])
        throw std::invalid_argument("channel()");

    //if (weechat::channel::search(&account, id))
    //    throw std::invalid_argument("duplicate");

    buffer = weechat::channel::create_buffer(type, name);
    if (!buffer)
        throw std::invalid_argument("buffer fail");
    else if (type == weechat::channel::chat_type::PM)
    {
        auto muc_channel = account.channels.find(jid(account.context,
                                                                               id).bare.data());
        if (muc_channel != account.channels.end())
        {
            weechat_buffer_merge(buffer, muc_channel->second.buffer);
        }
    }

    typing_hook_timer = weechat_hook_timer(1 * 1000, 0, 0,
                                           &weechat::channel::typing_cb,
                                           this, nullptr);

    self_typing_hook_timer = weechat_hook_timer(1 * 1000, 0, 0,
                                                &weechat::channel::self_typing_cb,
                                                this, nullptr);

    omemo.enabled = type == weechat::channel::chat_type::PM ? 1 : 0;
    omemo.devicelist_requests = weechat_hashtable_new(64,
            WEECHAT_HASHTABLE_STRING, WEECHAT_HASHTABLE_POINTER, nullptr, nullptr);
    omemo.bundle_requests = weechat_hashtable_new(64,
            WEECHAT_HASHTABLE_STRING, WEECHAT_HASHTABLE_POINTER, nullptr, nullptr);

    add_nicklist_groups();

    if (type != weechat::channel::chat_type::MUC)
    {
        time_t start = time(NULL);
        struct tm *ago = gmtime(&start);
        ago->tm_mday -= 7;
        start = mktime(ago);
        fetch_mam(nullptr, &start, nullptr, nullptr);
    }
}

void weechat::channel::member_speaking_add_to_list(const char *nick, int highlight)
{
    int size, to_remove, i;
    struct t_weelist_item *ptr_item;

    /* create list if it does not exist */
    if (!members_speaking[highlight])
        members_speaking[highlight] = weechat_list_new();

    /* remove item if it was already in list */
    ptr_item = weechat_list_casesearch(members_speaking[highlight], nick);
    if (ptr_item)
        weechat_list_remove(members_speaking[highlight], ptr_item);

    /* add nick in list */
    weechat_list_add(members_speaking[highlight], nick,
                     WEECHAT_LIST_POS_END, NULL);

    /* reduce list size if it's too big */
    size = weechat_list_size(members_speaking[highlight]);
    if (size > CHANNEL_MEMBERS_SPEAKING_LIMIT)
    {
        to_remove = size - CHANNEL_MEMBERS_SPEAKING_LIMIT;
        for (i = 0; i < to_remove; i++)
        {
            weechat_list_remove(
                members_speaking[highlight],
                weechat_list_get(members_speaking[highlight], 0));
        }
    }
}

void weechat::channel::member_speaking_add(const char *nick, int highlight)
{
    if (highlight < 0)
        highlight = 0;
    if (highlight > 1)
        highlight = 1;
    if (highlight)
        weechat::channel::member_speaking_add_to_list(nick, 1);

    weechat::channel::member_speaking_add_to_list(nick, 0);
}

void weechat::channel::member_speaking_rename(const char *old_nick, const char *new_nick)
{
    struct t_weelist_item *ptr_item;
    int i;

    for (i = 0; i < 2; i++)
    {
        if (members_speaking[i])
        {
            ptr_item = weechat_list_search(members_speaking[i], old_nick);
            if (ptr_item)
                weechat_list_set(ptr_item, new_nick);
        }
    }
}

void weechat::channel::member_speaking_rename_if_present(const char *nick)
{
    struct t_weelist_item *ptr_item;
    int i, j, list_size;

    for (i = 0; i < 2; i++)
    {
        if (members_speaking[i])
        {
            list_size = weechat_list_size(members_speaking[i]);
            for (j = 0; j < list_size; j++)
            {
                ptr_item = weechat_list_get(members_speaking[i], j);
                if (ptr_item && (weechat_strcasecmp(weechat_list_string(ptr_item),
                                                    nick) == 0))
                    weechat_list_set(ptr_item, nick);
            }
        }
    }
}

int weechat::channel::typing_cb(const void *pointer, void *data, int remaining_calls)
{
    weechat::channel *channel;
    const char *localvar;
    unsigned typecount;
    time_t now;

    (void) data;
    (void) remaining_calls;

    if (!pointer)
        return WEECHAT_RC_ERROR;

    channel = (weechat::channel *)pointer;

    now = time(NULL);

    typecount = 0;

    for (auto ptr_typing = channel->typings.begin();
         ptr_typing != channel->typings.end(); ptr_typing++)
    {
        if (now - ptr_typing->ts > 5)
        {
            channel->typings.erase(ptr_typing);
        }

        typecount++;
    }

    localvar = weechat_buffer_get_string(channel->buffer, "localvar_typing");
    if (!localvar || strncmp(localvar, typecount > 0 ? "1" : "0", 1) != 0)
        weechat_buffer_set(channel->buffer, "localvar_set_typing",
                           typecount > 0 ? "1" : "0");
    weechat_bar_item_update("typing");

    return WEECHAT_RC_OK;
}

weechat::channel::typing *weechat::channel::typing_search(const char *id)
{
    if (!id)
        return nullptr;

    for (auto& ptr_typing : typings)
    {
        if (weechat_strcasecmp(ptr_typing.id, id) == 0)
            return &ptr_typing;
    }

    return nullptr;
}

int weechat::channel::add_typing(weechat::user *user)
{
    weechat::channel::typing *new_typing;
    int ret = 0;

    new_typing = weechat::channel::typing_search(user->id);
    if (!new_typing)
    {
        new_typing = new weechat::channel::typing();
        new_typing->id = strdup(user->id);
        new_typing->name = strdup(user->profile.display_name);

        ret = 1;
    }
    new_typing->ts = time(nullptr);

    weechat::channel::typing_cb(this, nullptr, 0);

    return ret;
}

int weechat::channel::self_typing_cb(const void *pointer, void *data, int remaining_calls)
{
    time_t now;

    (void) data;
    (void) remaining_calls;

    if (!pointer)
        return WEECHAT_RC_ERROR;

    weechat::channel *channel = (weechat::channel *)pointer;

    now = time(NULL);

    for (auto ptr_typing = channel->self_typings.begin();
         ptr_typing != channel->self_typings.end(); ptr_typing++)
    {
        if (now - ptr_typing->ts > 10)
        {
            channel->send_paused(ptr_typing->user);
            channel->self_typings.erase(ptr_typing);
        }
    }

    return WEECHAT_RC_OK;
}

weechat::channel::typing *weechat::channel::self_typing_search(weechat::user *user)
{
    for (auto& ptr_typing : typings)
    {
        if (user == ptr_typing.user)
            return &ptr_typing;
    }

    return nullptr;
}

int weechat::channel::add_self_typing(weechat::user *user)
{
    weechat::channel::typing *new_typing;
    int ret = 0;

    new_typing = self_typing_search(user);
    if (!new_typing)
    {
        new_typing = new weechat::channel::typing();
        new_typing->user = user;
        new_typing->name = user ? strdup(user->profile.display_name) : NULL;

        ret = 1;
    }

    self_typing_cb(this, nullptr, 0);

    return ret;
}

weechat::channel::~channel()
{
    if (typing_hook_timer)
        weechat_unhook(typing_hook_timer);
    if (self_typing_hook_timer)
        weechat_unhook(self_typing_hook_timer);

    if (members_speaking[0])
        weechat_list_free(members_speaking[0]);
    if (members_speaking[1])
        weechat_list_free(members_speaking[1]);
}

void weechat::channel::update_topic(const char* topic, const char* creator, int last_set)
{
    if (this->topic.value)
        ::free(this->topic.value);
    if (this->topic.creator)
        ::free(this->topic.creator);
    this->topic.value = (topic) ? strdup(topic) : NULL;
    this->topic.creator = (creator) ? strdup(creator) : NULL;
    this->topic.last_set = last_set;

    if (this->topic.value)
        weechat_buffer_set(buffer, "title", topic);
    else
        weechat_buffer_set(buffer, "title", "");
}

void weechat::channel::update_name(const char* name)
{
    if (name)
        weechat_buffer_set(buffer, "short_name", name);
    else
        weechat_buffer_set(buffer, "short_name", "");
}

weechat::channel::member *weechat::channel::add_member(const char *id, const char *client)
{
    weechat::channel::member *member;
    weechat::user *user;

    user = user::search(&account, id);

    if (this->id == id && type == weechat::channel::chat_type::MUC)
    {
        weechat_printf_date_tags(buffer, 0, "log2", "%sMUC: %s",
                                 weechat_prefix("network"), id);
        return nullptr;
    }

    if (!(member = member_search(id)))
    {
        member = new weechat::channel::member();
        member->id = strdup(id);

        member->role = NULL;
        member->affiliation = NULL;
    }
    else if (user)
        user->nicklist_remove(&account, this);

    if (user)
        user->nicklist_add(&account, this);
    else return member; // TODO: !!

    char *jid_bare = xmpp_jid_bare(account.context, user->id);
    char *jid_resource = xmpp_jid_resource(account.context, user->id);
    if (weechat_strcasecmp(jid_bare, id) == 0
             && type == weechat::channel::chat_type::MUC)
        weechat_printf_date_tags(buffer, 0, "xmpp_presence,enter,log4", "%s%s%s%s%s %s%s%s%s %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                                 weechat_prefix("join"),
                                 user->as_prefix_raw().data(),
                                 client ? " (" : "",
                                 client ? client : "",
                                 client ? ")" : "",
                                 user->profile.status ? "is " : "",
                                 weechat_color("irc.color.message_join"),
                                 user->profile.status ? user->profile.status : (user->profile.idle ? "idle" : "entered"),
                                 weechat_color("reset"),
                                 id,
                                 user->profile.status_text ? " [" : "",
                                 user->profile.status_text ? user->profile.status_text : "",
                                 user->profile.status_text ? "]" : "",
                                 weechat_color("yellow"), " as ", weechat_color("reset"),
                                 user->profile.affiliation ? user->profile.affiliation : "",
                                 user->profile.affiliation ? " " : "",
                                 user->profile.role,
                                 user->profile.pgp_id ? weechat_color("gray") : "",
                                 user->profile.pgp_id ? " with PGP:" : "",
                                 user->profile.pgp_id ? user->profile.pgp_id : "",
                                 user->profile.pgp_id ? weechat_color("reset") : "");
    else
        weechat_printf_date_tags(buffer, 0, "xmpp_presence,enter,log4", "%s%s (%s) %s%s%s%s %s%s%s%s%s%s%s%s%s",
                                 weechat_prefix("join"),
                                 jid_resource ? user->as_prefix_raw().data() : "You",
                                 jid_resource ? jid_resource : user->as_prefix_raw().data(),
                                 user->profile.status ? "is " : "",
                                 weechat_color("irc.color.message_join"),
                                 user->profile.status ? user->profile.status : (user->profile.idle ? "idle" : "entered"),
                                 weechat_color("reset"),
                                 user->profile.idle ? "since " : "",
                                 user->profile.idle ? user->profile.idle->data() : "",
                                 user->profile.status_text ? " [" : "",
                                 user->profile.status_text ? user->profile.status_text : "",
                                 user->profile.status_text ? "]" : "",
                                 user->profile.pgp_id || user->profile.omemo ? weechat_color("gray") : "",
                                 user->profile.pgp_id || user->profile.omemo ? " with " : "",
                                 user->profile.pgp_id ? "PGP:" : "",
                                 user->profile.pgp_id ? user->profile.pgp_id : "",
                                 user->profile.omemo && user->profile.pgp_id ? " and " : "",
                                 user->profile.omemo ? "OMEMO" : "",
                                 user->profile.pgp_id || user->profile.omemo ? weechat_color("reset") : "");

    return member;
}

weechat::channel::member *weechat::channel::member_search(const char *id)
{
    if (!id)
        return nullptr;

    for (auto& ptr_member : members)
    {
        if (weechat_strcasecmp(ptr_member.second.id, id) == 0)
            return &ptr_member.second;
    }

    return nullptr;
}

weechat::channel::member *weechat::channel::remove_member(const char *id, const char *reason)
{
    weechat::channel::member *member;
    weechat::user *user;

    user = user::search(&account, id);
    if (user)
        user->nicklist_remove(&account, this);
    else return nullptr; // TODO !!

    member = member_search(id);

    char *jid_bare = xmpp_jid_bare(account.context, user->id);
    char *jid_resource = xmpp_jid_resource(account.context, user->id);
    if (weechat_strcasecmp(jid_bare, id) == 0
        && type == weechat::channel::chat_type::MUC)
        weechat_printf_date_tags(buffer, 0, "xmpp_presence,leave,log4",
                                 "%s%s %sleft%s %s %s%s%s",
                                 weechat_prefix("quit"),
                                 jid_resource,
                                 weechat_color("irc.color.message_quit"),
                                 weechat_color("reset"),
                                 id,
                                 reason ? "[" : "",
                                 reason ? reason : "",
                                 reason ? "]" : "");
    else
        weechat_printf_date_tags(buffer, 0, "xmpp_presence,leave,log4",
                                 "%s%s (%s) %sleft%s %s %s%s%s",
                                 weechat_prefix("quit"),
                                 xmpp_jid_bare(account.context, user->id),
                                 xmpp_jid_resource(account.context, user->id),
                                 weechat_color("irc.color.message_quit"),
                                 weechat_color("reset"),
                                 id,
                                 reason ? "[" : "",
                                 reason ? reason : "",
                                 reason ? "]" : "");

    return member;
}

int weechat::channel::send_message(std::string to, std::string body,
                                   std::optional<std::string> oob)
{
    xmpp_stanza_t *message = xmpp_message_new(account.context,
                    type == weechat::channel::chat_type::MUC
                    ? "groupchat" : "chat",
                    to.data(), NULL);

    char *id = xmpp_uuid_gen(account.context);
    xmpp_stanza_set_id(message, id);
    xmpp_free(account.context, id);
    xmpp_message_set_body(message, body.data());

    if (oob)
    {
        xmpp_stanza_t *message__x = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__x, "x");
        xmpp_stanza_set_ns(message__x, "jabber:x:oob");

        xmpp_stanza_t *message__x__url = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__x__url, "url");

        xmpp_stanza_t *message__x__url__text = xmpp_stanza_new(account.context);
        xmpp_stanza_set_text(message__x__url__text, oob->data());
        xmpp_stanza_add_child(message__x__url, message__x__url__text);
        xmpp_stanza_release(message__x__url__text);

        xmpp_stanza_add_child(message__x, message__x__url);
        xmpp_stanza_release(message__x__url);

        xmpp_stanza_add_child(message, message__x);
        xmpp_stanza_release(message__x);
    }

    xmpp_stanza_t *message__active = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__active, "active");
    xmpp_stanza_set_ns(message__active, "http://jabber.org/protocol/chatstates");
    xmpp_stanza_add_child(message, message__active);
    xmpp_stanza_release(message__active);

    xmpp_stanza_t *message__request = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__request, "request");
    xmpp_stanza_set_ns(message__request, "urn:xmpp:receipts");
    xmpp_stanza_add_child(message, message__request);
    xmpp_stanza_release(message__request);

    xmpp_stanza_t *message__markable = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__markable, "markable");
    xmpp_stanza_set_ns(message__markable, "urn:xmpp:chat-markers:0");
    xmpp_stanza_add_child(message, message__markable);
    xmpp_stanza_release(message__markable);

    xmpp_stanza_t *message__store = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__store, "store");
    xmpp_stanza_set_ns(message__store, "urn:xmpp:hints");
    xmpp_stanza_add_child(message, message__store);
    xmpp_stanza_release(message__store);

    xmpp_send(account.connection, message);
    xmpp_stanza_release(message);
    if (type != weechat::channel::chat_type::MUC)
        weechat_printf_date_tags(buffer, 0,
                                 "xmpp_message,message,private,notify_none,self_msg,log1",
                                 "%s\t%s",
                                 user::search(&account, account.jid().data())->as_prefix_raw().data(),
                                 body.data());

    return WEECHAT_RC_OK;
}

int weechat::channel::send_message(const char *to, const char *body)
{
    send_reads();

    xmpp_stanza_t *message = xmpp_message_new(account.context,
                    type == weechat::channel::chat_type::MUC
                    ? "groupchat" : "chat",
                    to, NULL);

    char *id = xmpp_uuid_gen(account.context);
    xmpp_stanza_set_id(message, id);
    xmpp_free(account.context, id);

    if (account.omemo && omemo.enabled)
    {
        xmpp_stanza_t *encrypted = account.omemo.encode(&account, to, body);
        if (!encrypted)
        {
            weechat_printf_date_tags(buffer, 0, "notify_none", "%s%s",
                                     weechat_prefix("error"), "OMEMO Encryption Error");
            set_transport(weechat::channel::transport::PLAIN, 1);
            xmpp_stanza_release(message);
            return WEECHAT_RC_ERROR;
        }
        xmpp_stanza_add_child(message, encrypted);
        xmpp_stanza_release(encrypted);

        xmpp_stanza_t *message__encryption = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__encryption, "encryption");
        xmpp_stanza_set_ns(message__encryption, "urn:xmpp:eme:0");
        xmpp_stanza_set_attribute(message__encryption, "namespace",
                "eu.siacs.conversations.axolotl");
        xmpp_stanza_set_attribute(message__encryption, "name", "OMEMO");
        xmpp_stanza_add_child(message, message__encryption);
        xmpp_stanza_release(message__encryption);

        xmpp_message_set_body(message, OMEMO_ADVICE);

        set_transport(weechat::channel::transport::OMEMO, 0);
    }
    else if (pgp.enabled && !pgp.ids.empty())
    {
        xmpp_stanza_t *message__x = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__x, "x");
        xmpp_stanza_set_ns(message__x, "jabber:x:encrypted");

        xmpp_stanza_t *message__x__text = xmpp_stanza_new(account.context);
        char *ciphertext = account.pgp.encrypt(buffer, account.pgp_keyid().data(), std::vector(pgp.ids.begin(), pgp.ids.end()), body);
        if (ciphertext)
            xmpp_stanza_set_text(message__x__text, ciphertext);
        else
        {
            weechat_printf_date_tags(buffer, 0, "notify_none", "%s%s",
                                     weechat_prefix("error"), "PGP Error");
            set_transport(weechat::channel::transport::PLAIN, 1);
            xmpp_stanza_release(message);
            return WEECHAT_RC_ERROR;
        }
        ::free(ciphertext);

        xmpp_stanza_add_child(message__x, message__x__text);
        xmpp_stanza_release(message__x__text);

        xmpp_stanza_add_child(message, message__x);
        xmpp_stanza_release(message__x);

        xmpp_stanza_t *message__encryption = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__encryption, "encryption");
        xmpp_stanza_set_ns(message__encryption, "urn:xmpp:eme:0");
        xmpp_stanza_set_attribute(message__encryption, "namespace", "jabber:x:encryption");

        xmpp_stanza_add_child(message, message__encryption);
        xmpp_stanza_release(message__encryption);

        xmpp_message_set_body(message, weechat::xmpp::PGP_ADVICE);

        set_transport(weechat::channel::transport::PGP, 0);
    }
    else
    {
        xmpp_message_set_body(message, body);

        set_transport(weechat::channel::transport::PLAIN, 0);
    }

    static const std::regex pattern("https?:[^ ]*");
    std::cmatch match;
    if (transport == weechat::channel::transport::PLAIN &&
            std::regex_search(body, match, pattern)
            && match[0].matched && !match.prefix().length())
    {
        std::string url { &*match[0].first, static_cast<size_t>(match[0].length()) };

        do {
            struct t_hashtable *options = weechat_hashtable_new(8,
                    WEECHAT_HASHTABLE_STRING, WEECHAT_HASHTABLE_STRING,
                    NULL, NULL);
            if (!options) { return WEECHAT_RC_ERROR; };
            weechat_hashtable_set(options, "header", "1");
            weechat_hashtable_set(options, "nobody", "1");
            auto command = "url:" + url;
            const int timeout = 30000;
            struct message_task {
                weechat::channel& channel;
                std::string to;
                std::string body;
                std::string url;
            };
            auto *task = new message_task { *this, to, body, url };
            auto callback = [](const void *pointer, void *,
                    const char *, int ret, const char *out, const char *err) {
                auto task = static_cast<const message_task*>(pointer);
                if (!task) return WEECHAT_RC_ERROR;

                if (ret == 0)
                {
                    const std::string_view prefix = "content-type: ";
                    std::istringstream ss(out ? out : "");
                    std::string line, mime;
                    while (std::getline(ss, line)) {
                        std::transform(line.begin(), line.end(), line.begin(),
                                [](char c) -> char { return std::tolower(c); });
                        if (line.starts_with(prefix)) {
                            mime = line.substr(prefix.size());
                            break;
                        }
                    }
                    if (mime.starts_with("image") || mime.starts_with("video"))
                    {
                        weechat_printf_date_tags(task->channel.buffer, 0,
                                "notify_none,no_log", "[oob]\t%s%s",
                                weechat_color("gray"), mime.data());
                        task->channel.send_message(task->to, task->body, { task->url });
                    }
                    else
                    {
                        weechat_printf_date_tags(task->channel.buffer, 0,
                                "notify_none,no_log", "[curl]\t%s%s",
                                weechat_color("red"), err);
                        task->channel.send_message(task->to.data(), task->body.data());
                    }
                }
                else
                {
                    task->channel.send_message(task->to.data(), task->body.data());
                }

                delete task;
                return WEECHAT_RC_OK;
            };
            struct t_hook *process_hook =
                weechat_hook_process_hashtable(command.data(), options, timeout,
                    callback, task, nullptr);
            weechat_hashtable_free(options);
            (void) process_hook;
            return WEECHAT_RC_OK;
        } while(0);
    }

    xmpp_stanza_t *message__active = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__active, "active");
    xmpp_stanza_set_ns(message__active, "http://jabber.org/protocol/chatstates");
    xmpp_stanza_add_child(message, message__active);
    xmpp_stanza_release(message__active);

    xmpp_stanza_t *message__request = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__request, "request");
    xmpp_stanza_set_ns(message__request, "urn:xmpp:receipts");
    xmpp_stanza_add_child(message, message__request);
    xmpp_stanza_release(message__request);

    xmpp_stanza_t *message__markable = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__markable, "markable");
    xmpp_stanza_set_ns(message__markable, "urn:xmpp:chat-markers:0");
    xmpp_stanza_add_child(message, message__markable);
    xmpp_stanza_release(message__markable);

    xmpp_stanza_t *message__store = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__store, "store");
    xmpp_stanza_set_ns(message__store, "urn:xmpp:hints");
    xmpp_stanza_add_child(message, message__store);
    xmpp_stanza_release(message__store);

    xmpp_send(account.connection, message);
    xmpp_stanza_release(message);
    if (type != weechat::channel::chat_type::MUC)
        weechat_printf_date_tags(buffer, 0,
                                 "xmpp_message,message,private,notify_none,self_msg,log1",
                                 "%s\t%s",
                                 user::search(&account, account.jid().data())->as_prefix_raw().data(),
                                 body);

    return WEECHAT_RC_OK;
}

void weechat::channel::send_reads()
{
    auto i = std::begin(unreads);

    while (i != std::end(unreads))
    {
        auto* unread = &*i;

        xmpp_stanza_t *message = xmpp_message_new(account.context, NULL,
                                                    id.data(), NULL);

        xmpp_stanza_t *message__displayed = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__displayed, "displayed");
        xmpp_stanza_set_ns(message__displayed, "urn:xmpp:chat-markers:0");
        xmpp_stanza_set_id(message__displayed, unread->id);
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

        xmpp_stanza_add_child(message, message__displayed);
        xmpp_stanza_release(message__displayed);

        xmpp_send(account.connection, message);
        xmpp_stanza_release(message);

        i = unreads.erase(i);
    }
}

void weechat::channel::send_typing(weechat::user *user)
{
    if (add_self_typing(user))
    {
        xmpp_stanza_t *message = xmpp_message_new(account.context,
                                                  type == weechat::channel::chat_type::MUC
                                                  ? "groupchat" : "chat",
                                                  (user ? user->id : id).data(), NULL);

        xmpp_stanza_t *message__composing = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(message__composing, "composing");
        xmpp_stanza_set_ns(message__composing, "http://jabber.org/protocol/chatstates");

        xmpp_stanza_add_child(message, message__composing);
        xmpp_stanza_release(message__composing);

        xmpp_send(account.connection, message);
        xmpp_stanza_release(message);
    }
}

void weechat::channel::send_paused(weechat::user *user)
{
    xmpp_stanza_t *message = xmpp_message_new(account.context,
                                              type == weechat::channel::chat_type::MUC
                                              ? "groupchat" : "chat",
                                              (user ? user->id : id).data(), NULL);

    xmpp_stanza_t *message__paused = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(message__paused, "paused");
    xmpp_stanza_set_ns(message__paused, "http://jabber.org/protocol/chatstates");

    xmpp_stanza_add_child(message, message__paused);
    xmpp_stanza_release(message__paused);

    xmpp_send(account.connection, message);
    xmpp_stanza_release(message);
}

void weechat::channel::fetch_mam(const char *id, time_t *start, time_t *end, const char* after)
{
    xmpp_stanza_t *iq = xmpp_iq_new(account.context, "set", "juliet1");
    xmpp_stanza_set_id(iq, id ? id : xmpp_uuid_gen(account.context));

    xmpp_stanza_t *query = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(query, "query");
    xmpp_stanza_set_ns(query, "urn:xmpp:mam:2");

    xmpp_stanza_t *x = xmpp_stanza_new(account.context);
    xmpp_stanza_set_name(x, "x");
    xmpp_stanza_set_ns(x, "jabber:x:data");
    xmpp_stanza_set_attribute(x, "type", "result");

    xmpp_stanza_t *field, *value, *text;

    {
        field = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "FORM_TYPE");
        xmpp_stanza_set_attribute(field, "type", "hidden");

        value = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account.context);
        xmpp_stanza_set_text(text, "urn:xmpp:mam:2");
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    {
        field = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "with");

        value = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account.context);
        xmpp_stanza_set_text(text, id);
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    if (start)
    {
        field = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "start");

        value = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account.context);
        char time[256] = {0};
        strftime(time, sizeof(time), "%Y-%m-%dT%H:%M:%SZ", gmtime(start));
        xmpp_stanza_set_text(text, time);
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    if (end)
    {
        field = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(field, "field");
        xmpp_stanza_set_attribute(field, "var", "end");

        value = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(value, "value");

        text = xmpp_stanza_new(account.context);
        char time[256] = {0};
        strftime(time, sizeof(time), "%Y-%m-%dT%H:%M:%SZ", gmtime(end));
        xmpp_stanza_set_text(text, time);
        xmpp_stanza_add_child(value, text);
        xmpp_stanza_release(text);

        xmpp_stanza_add_child(field, value);
        xmpp_stanza_release(value);

        xmpp_stanza_add_child(x, field);
        xmpp_stanza_release(field);
    }

    xmpp_stanza_add_child(query, x);
    xmpp_stanza_release(x);

    if (after)
    {
        xmpp_stanza_t *set, *set__after, *set__after__text;

        set = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(set, "set");
        xmpp_stanza_set_ns(set, "http://jabber.org/protocol/rsm");

        set__after = xmpp_stanza_new(account.context);
        xmpp_stanza_set_name(set__after, "after");

        set__after__text = xmpp_stanza_new(account.context);
        xmpp_stanza_set_text(set__after__text, after);
        xmpp_stanza_add_child(set__after, set__after__text);
        xmpp_stanza_release(set__after__text);

        xmpp_stanza_add_child(set, set__after);
        xmpp_stanza_release(set__after);

        xmpp_stanza_add_child(query, set);
        xmpp_stanza_release(set);
    }
    else
        account.add_mam_query(id, xmpp_stanza_get_id(iq), { *start }, { *end });

    xmpp_stanza_add_child(iq, query);
    xmpp_stanza_release(query);

    xmpp_send(account.connection, iq);
    xmpp_stanza_release(iq);
}
