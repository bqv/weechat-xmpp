// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "omemo.h"
#include "account.h"
#include "user.h"
#include "channel.h"
#include "input.h"
#include "buffer.h"

struct t_channel *channel__search(struct t_account *account,
                                  const char *id)
{
    struct t_channel *ptr_channel;

    if (!account || !id)
        return NULL;

    for (ptr_channel = account->channels; ptr_channel;
         ptr_channel = ptr_channel->next_channel)
    {
        if (weechat_strcasecmp(ptr_channel->id, id) == 0)
            return ptr_channel;
    }

    return NULL;
}

struct t_gui_buffer *channel__search_buffer(struct t_account *account,
                                            enum t_channel_type type,
                                            const char *name)
{
    struct t_hdata *hdata_buffer;
    struct t_gui_buffer *ptr_buffer;
    const char *ptr_type, *ptr_account_name, *ptr_channel_name;

    hdata_buffer = weechat_hdata_get("buffer");
    ptr_buffer = weechat_hdata_get_list(hdata_buffer, "gui_buffers");

    while (ptr_buffer)
    {
        if (weechat_buffer_get_pointer(ptr_buffer, "plugin") == weechat_plugin)
        {
            ptr_type = weechat_buffer_get_string(ptr_buffer, "localvar_type");
            ptr_account_name = weechat_buffer_get_string(ptr_buffer,
                                                           "localvar_server");
            ptr_channel_name = weechat_buffer_get_string(ptr_buffer,
                                                         "localvar_channel");
            if (ptr_type && ptr_type[0]
                && ptr_account_name && ptr_account_name[0]
                && ptr_channel_name && ptr_channel_name[0]
                && (   ((  (type == CHANNEL_TYPE_MUC))
                        && (strcmp(ptr_type, "channel") == 0))
                    || ((  (type == CHANNEL_TYPE_PM))
                        && (strcmp(ptr_type, "private") == 0)))
                && (strcmp(ptr_account_name, account->name) == 0)
                && (weechat_strcasecmp(ptr_channel_name, name) == 0))
            {
                return ptr_buffer;
            }
        }
        ptr_buffer = weechat_hdata_move(hdata_buffer, ptr_buffer, 1);
    }

    return NULL;
}

struct t_gui_buffer *channel__create_buffer(struct t_account *account,
                                            enum t_channel_type type,
                                            const char *name)
{
    struct t_gui_buffer *ptr_buffer;
    int buffer_created;
    const char *short_name, *localvar_channel;
    char buffer_name[256];

    buffer_created = 0;

    snprintf(buffer_name, sizeof(buffer_name),
             "%s.%s", account->name, name);

    ptr_buffer = channel__search_buffer(account, type, name);
    if (ptr_buffer)
    {
        weechat_nicklist_remove_all(ptr_buffer);
    }
    else
    {
        ptr_buffer = weechat_buffer_new(buffer_name,
                                        &input__data_cb, NULL, NULL,
                                        &buffer__close_cb, NULL, NULL);
        if (!ptr_buffer)
            return NULL;

        buffer_created = 1;
    }

    if (buffer_created)
    {
        if (!weechat_buffer_get_integer(ptr_buffer, "short_name_is_set"))
            weechat_buffer_set(ptr_buffer, "short_name", name);
    }
    else
    {
        short_name = weechat_buffer_get_string (ptr_buffer, "short_name");
        localvar_channel = weechat_buffer_get_string(ptr_buffer,
                                                     "localvar_channel");

        if (!short_name ||
            (localvar_channel && (strcmp(localvar_channel, short_name) == 0)))
        {
            weechat_buffer_set(ptr_buffer, "short_name",
                               xmpp_jid_node(account->context, name));
        }
    }
    if(!(account_nickname(account) && strlen(account_nickname(account))))
        account_option_set(account, ACCOUNT_OPTION_NICKNAME,
                           xmpp_jid_node(account->context, account_jid(account)));

    weechat_buffer_set(ptr_buffer, "name", name);
    weechat_buffer_set(ptr_buffer, "localvar_set_type",
                       (type == CHANNEL_TYPE_PM) ? "private" : "channel");
    weechat_buffer_set(ptr_buffer, "localvar_set_nick",
                       account_nickname(account));
    weechat_buffer_set(ptr_buffer, "localvar_set_server", account->name);
    weechat_buffer_set(ptr_buffer, "localvar_set_channel", name);

    if (buffer_created)
    {
        (void) weechat_hook_signal_send ("logger_backlog",
                                         WEECHAT_HOOK_SIGNAL_POINTER,
                                         ptr_buffer);
        weechat_buffer_set(ptr_buffer, "input_get_unknown_commands", "1");
        if (type != CHANNEL_TYPE_PM)
        {
            weechat_buffer_set(ptr_buffer, "nicklist", "1");
            weechat_buffer_set(ptr_buffer, "nicklist_display_groups", "0");
            weechat_buffer_set_pointer(ptr_buffer, "nicklist_callback",
                                       &buffer__nickcmp_cb);
            weechat_buffer_set_pointer(ptr_buffer, "nicklist_callback_pointer",
                                       account);
        }

        weechat_buffer_set(ptr_buffer, "highlight_words_add",
                           account_nickname(account));
        weechat_buffer_set(ptr_buffer, "highlight_tags_restrict",
                           "message");
    }

    return ptr_buffer;
}

void channel__add_nicklist_groups(struct t_account *account,
                                  struct t_channel *channel)
{
    struct t_gui_buffer *ptr_buffer;
    char str_group[32];

    if (channel && channel->type == CHANNEL_TYPE_PM)
        return;

    ptr_buffer = channel ? channel->buffer : account->buffer;

    snprintf(str_group, sizeof(str_group), "%03d|%s",
             000, "+");
    weechat_nicklist_add_group(ptr_buffer, NULL, str_group,
                               "weechat.color.nicklist_group", 1);
    snprintf(str_group, sizeof(str_group), "%03d|%s",
             999, "...");
    weechat_nicklist_add_group(ptr_buffer, NULL, str_group,
                               "weechat.color.nicklist_group", 1);
}

struct t_channel *channel__new(struct t_account *account,
                               enum t_channel_type type,
                               const char *id, const char *name)
{
    struct t_channel *new_channel, *ptr_channel;
    struct t_gui_buffer *ptr_buffer;
    struct t_hook *typing_timer;

    if (!account || !id || !name || !name[0])
        return NULL;

    ptr_channel = channel__search(account, id);
    if (ptr_channel)
    {
        return ptr_channel;
    }

    ptr_buffer = channel__create_buffer(account, type, name);
    if (!ptr_buffer)
        return NULL;

    if ((new_channel = malloc(sizeof(*new_channel))) == NULL)
        return NULL;

    typing_timer = weechat_hook_timer(1 * 1000, 0, 0,
                                      &channel__typing_cb,
                                      new_channel, NULL);

    new_channel->type = type;
    new_channel->id = strdup(id);
    new_channel->name = strdup(name);

    new_channel->topic.value = NULL;
    new_channel->topic.creator = NULL;
    new_channel->topic.last_set = 0;

    new_channel->creator = NULL;
    new_channel->last_read = 0.0;
    new_channel->unread_count = 0;
    new_channel->unread_count_display = 0;

    new_channel->typing_hook_timer = typing_timer;
    new_channel->members_speaking[0] = NULL;
    new_channel->members_speaking[1] = NULL;
    new_channel->typings = NULL;
    new_channel->last_typing = NULL;
    new_channel->members = NULL;
    new_channel->last_member = NULL;
    new_channel->buffer = ptr_buffer;
    new_channel->buffer_as_string = NULL;

    new_channel->prev_channel = account->last_channel;
    new_channel->next_channel = NULL;
    if (account->last_channel)
        (account->last_channel)->next_channel = new_channel;
    else
        account->channels = new_channel;
    account->last_channel = new_channel;

    return new_channel;
}

void channel__member_speaking_add_to_list(struct t_channel *channel,
                                          const char *nick,
                                          int highlight)
{
    int size, to_remove, i;
    struct t_weelist_item *ptr_item;

    /* create list if it does not exist */
    if (!channel->members_speaking[highlight])
        channel->members_speaking[highlight] = weechat_list_new();

    /* remove item if it was already in list */
    ptr_item = weechat_list_casesearch(channel->members_speaking[highlight], nick);
    if (ptr_item)
        weechat_list_remove(channel->members_speaking[highlight], ptr_item);

    /* add nick in list */
    weechat_list_add(channel->members_speaking[highlight], nick,
                     WEECHAT_LIST_POS_END, NULL);

    /* reduce list size if it's too big */
    size = weechat_list_size(channel->members_speaking[highlight]);
    if (size > CHANNEL_MEMBERS_SPEAKING_LIMIT)
    {
        to_remove = size - CHANNEL_MEMBERS_SPEAKING_LIMIT;
        for (i = 0; i < to_remove; i++)
        {
            weechat_list_remove(
                channel->members_speaking[highlight],
                weechat_list_get(channel->members_speaking[highlight], 0));
        }
    }
}

void channel__member_speaking_add(struct t_channel *channel,
                                  const char *nick, int highlight)
{
    if (highlight < 0)
        highlight = 0;
    if (highlight > 1)
        highlight = 1;
    if (highlight)
        channel__member_speaking_add_to_list(channel, nick, 1);

    channel__member_speaking_add_to_list(channel, nick, 0);
}

void channel__member_speaking_rename(struct t_channel *channel,
                                     const char *old_nick,
                                     const char *new_nick)
{
    struct t_weelist_item *ptr_item;
    int i;

    for (i = 0; i < 2; i++)
    {
        if (channel->members_speaking[i])
        {
            ptr_item = weechat_list_search(channel->members_speaking[i], old_nick);
            if (ptr_item)
                weechat_list_set(ptr_item, new_nick);
        }
    }
}

void channel__member_speaking_rename_if_present(struct t_account *account,
                                                struct t_channel *channel,
                                                const char *nick)
{
    struct t_weelist_item *ptr_item;
    int i, j, list_size;

    (void) account;

    for (i = 0; i < 2; i++)
    {
        if (channel->members_speaking[i])
        {
            list_size = weechat_list_size(channel->members_speaking[i]);
            for (j = 0; j < list_size; j++)
            {
                ptr_item = weechat_list_get (channel->members_speaking[i], j);
                if (ptr_item && (weechat_strcasecmp(weechat_list_string(ptr_item),
                                                    nick) == 0))
                    weechat_list_set(ptr_item, nick);
            }
        }
    }
}

void channel__typing_free(struct t_channel *channel,
                          struct t_channel_typing *typing)
{
    struct t_channel_typing *new_typings;

    if (!channel || !typing)
        return;

    /* remove typing from typings list */
    if (channel->last_typing == typing)
        channel->last_typing = typing->prev_typing;
    if (typing->prev_typing)
    {
        (typing->prev_typing)->next_typing = typing->next_typing;
        new_typings = channel->typings;
    }
    else
        new_typings = typing->next_typing;

    if (typing->next_typing)
        (typing->next_typing)->prev_typing = typing->prev_typing;

    /* free typing data */
    if (typing->id)
        free(typing->id);
    if (typing->name)
        free(typing->name);

    free(typing);

    channel->typings = new_typings;
}

void channel__typing_free_all(struct t_channel *channel)
{
    while (channel->typings)
        channel__typing_free(channel, channel->typings);
}

int channel__typing_cb(const void *pointer,
                       void *data,
                       int remaining_calls)
{
    struct t_channel_typing *ptr_typing, *next_typing;
    struct t_channel *channel;
    const char *localvar;
    unsigned typecount;
    time_t now;

    (void) data;
    (void) remaining_calls;

    if (!pointer)
        return WEECHAT_RC_ERROR;

    channel = (struct t_channel *)pointer;

    now = time(NULL);

    typecount = 0;

    for (ptr_typing = channel->typings; ptr_typing;
         ptr_typing = ptr_typing->next_typing)
    {
        next_typing = ptr_typing->next_typing;

        while (ptr_typing && now - ptr_typing->ts > 5)
        {
            channel__typing_free(channel, ptr_typing);
            ptr_typing = next_typing;
            if (ptr_typing)
                next_typing = ptr_typing->next_typing;
        }

        if (!ptr_typing)
            break;

        typecount++;
    }

    localvar = weechat_buffer_get_string(channel->buffer, "localvar_typing");
    if (!localvar || strncmp(localvar, typecount > 0 ? "1" : "0", 1) != 0)
        weechat_buffer_set(channel->buffer,
                           "localvar_set_typing",
                           typecount > 0 ? "1" : "0");
    weechat_bar_item_update("typing");

    return WEECHAT_RC_OK;
}

struct t_channel_typing *channel__typing_search(struct t_channel *channel,
                                                const char *id)
{
    struct t_channel_typing *ptr_typing;

    if (!channel || !id)
        return NULL;

    for (ptr_typing = channel->typings; ptr_typing;
         ptr_typing = ptr_typing->next_typing)
    {
        if (weechat_strcasecmp(ptr_typing->id, id) == 0)
            return ptr_typing;
    }

    return NULL;
}

void channel__add_typing(struct t_channel *channel,
                         struct t_user *user)
{
    struct t_channel_typing *new_typing;

    new_typing = channel__typing_search(channel, user->id);
    if (!new_typing)
    {
        new_typing = malloc(sizeof(*new_typing));
        new_typing->id = strdup(user->id);
        new_typing->name = strdup(user->profile.display_name);

        new_typing->prev_typing = channel->last_typing;
        new_typing->next_typing = NULL;
        if (channel->last_typing)
            (channel->last_typing)->next_typing = new_typing;
        else
            channel->typings = new_typing;
        channel->last_typing = new_typing;
    }
    new_typing->ts = time(NULL);

    channel__typing_cb(channel, NULL, 0);
}

void channel__member_free(struct t_channel *channel,
                          struct t_channel_member *member)
{
    struct t_channel_member *new_members;

    if (!channel || !member)
        return;

    /* remove member from members list */
    if (channel->last_member == member)
        channel->last_member = member->prev_member;
    if (member->prev_member)
    {
        (member->prev_member)->next_member = member->next_member;
        new_members = channel->members;
    }
    else
        new_members = member->next_member;

    if (member->next_member)
        (member->next_member)->prev_member = member->prev_member;

    /* free member data */
    if (member->id)
        free(member->id);
    if (member->role)
        free(member->role);
    if (member->affiliation)
        free(member->affiliation);

    free(member);

    channel->members = new_members;
}

void channel__member_free_all(struct t_channel *channel)
{
    while (channel->members)
        channel__member_free(channel, channel->members);
}

void channel__free(struct t_account *account,
                   struct t_channel *channel)
{
    struct t_channel *new_channels;

    if (!account || !channel)
        return;

    /* remove channel from channels list */
    if (account->last_channel == channel)
        account->last_channel = channel->prev_channel;
    if (channel->prev_channel)
    {
        (channel->prev_channel)->next_channel = channel->next_channel;
        new_channels = account->channels;
    }
    else
        new_channels = channel->next_channel;

    if (channel->next_channel)
        (channel->next_channel)->prev_channel = channel->prev_channel;

    /* free hooks */
    if (channel->typing_hook_timer)
        weechat_unhook(channel->typing_hook_timer);

    /* free linked lists */
    channel__typing_free_all(channel);
    channel__member_free_all(channel);

    /* free channel data */
    if (channel->id)
        free(channel->id);
    if (channel->name)
        free(channel->name);
    if (channel->topic.value)
        free(channel->topic.value);
    if (channel->topic.creator)
        free(channel->topic.creator);
    if (channel->creator)
        free(channel->creator);
    if (channel->members_speaking[0])
        weechat_list_free(channel->members_speaking[0]);
    if (channel->members_speaking[1])
        weechat_list_free(channel->members_speaking[1]);
    if (channel->buffer_as_string)
        free(channel->buffer_as_string);

    free(channel);

    account->channels = new_channels;
}

void channel__free_all(struct t_account *account)
{
    while (account->channels)
        channel__free(account, account->channels);
}

void channel__update_topic(struct t_channel *channel,
                           const char* topic,
                           const char* creator,
                           int last_set)
{
    if (channel->topic.value)
        free(channel->topic.value);
    if (channel->topic.creator)
        free(channel->topic.creator);
    channel->topic.value = (topic) ? strdup(topic) : NULL;
    channel->topic.creator = (creator) ? strdup(creator) : NULL;
    channel->topic.last_set = last_set;

    if (channel->topic.value)
        weechat_buffer_set(channel->buffer, "title", topic);
    else
        weechat_buffer_set(channel->buffer, "title", "");
}

struct t_channel_member *channel__add_member(struct t_account *account,
                                             struct t_channel *channel,
                                             const char *id)
{
    struct t_channel_member *member;
    struct t_user *user;

    member = malloc(sizeof(struct t_channel_member));
    member->id = strdup(id);

    member->role = NULL;
    member->affiliation = NULL;

    member->prev_member = channel->last_member;
    member->next_member = NULL;
    if (channel->last_member)
        (channel->last_member)->next_member = member;
    else
        channel->members = member;
    channel->last_member = member;

    user = user__search(account, id);
    if (user)
        user__nicklist_add(account, channel, user);

    char *jid_bare = xmpp_jid_bare(account->context, user->id);
    char *jid_resource = xmpp_jid_resource(account->context, user->id);
    if (weechat_strcasecmp(jid_bare, channel->id) == 0
        && channel->type == CHANNEL_TYPE_MUC)
        weechat_printf_date_tags(channel->buffer, 0, "xmpp_presence,enter,log4", "%s%s entered",
                                 weechat_prefix("join"),
                                 user__as_prefix_raw(account, jid_resource));
    else
        weechat_printf_date_tags(channel->buffer, 0, "xmpp_presence,enter,log4", "%s%s (%s) entered",
                                 weechat_prefix("join"),
                                 xmpp_jid_bare(account->context, user->id),
                                 user__as_prefix_raw(account,
                                                     xmpp_jid_resource(account->context, user->id)));

    return member;
}

struct t_channel_member *channel__member_search(struct t_channel *channel,
                                                const char *id)
{
    struct t_channel_member *ptr_member;

    if (!channel || !id)
        return NULL;

    for (ptr_member = channel->members; ptr_member;
         ptr_member = ptr_member->next_member)
    {
        if (weechat_strcasecmp(ptr_member->id, id) == 0)
            return ptr_member;
    }

    return NULL;
}

int channel__set_member_role(struct t_account *account,
                             struct t_channel *channel,
                             const char *id, const char *role)
{
    struct t_channel_member *member;
    struct t_user *user;

    user = user__search(account, id);
    if (!user)
        return 0;

    member = channel__member_search(channel, id);
    if (!member)
        return 0;

    member->role = strdup(role);

    return 1;
}

int channel__set_member_affiliation(struct t_account *account,
                                    struct t_channel *channel,
                                    const char *id, const char *affiliation)
{
    struct t_channel_member *member;
    struct t_user *user;

    user = user__search(account, id);
    if (!user)
        return 0;

    member = channel__member_search(channel, id);
    if (!member)
        return 0;

    member->affiliation = strdup(affiliation);

    return 1;
}

struct t_channel_member *channel__remove_member(struct t_account *account,
                                                struct t_channel *channel,
                                                const char *id)
{
    struct t_channel_member *member;
    struct t_user *user;

    user = user__search(account, id);
  //if (user)
  //    user__nicklist_remove(account, channel, user);

    member = channel__member_search(channel, id);
    if (member)
        channel__member_free(channel, member);

    char *jid_bare = xmpp_jid_bare(account->context, user->id);
    char *jid_resource = xmpp_jid_resource(account->context, user->id);
    if (weechat_strcasecmp(jid_bare, channel->id) == 0
        && channel->type == CHANNEL_TYPE_MUC)
        weechat_printf_date_tags(channel->buffer, 0, "xmpp_presence,leave,log4", "%s%s left",
                                 weechat_prefix("quit"),
                                 jid_resource);
    else
        weechat_printf_date_tags(channel->buffer, 0, "xmpp_presence,leave,log4", "%s%s (%s) left",
                                 weechat_prefix("quit"),
                                 xmpp_jid_bare(account->context, user->id),
                                 xmpp_jid_resource(account->context, user->id));

    return member;
}

void channel__send_message(struct t_account *account, struct t_channel *channel,
                           const char *to, const char *body)
{
    xmpp_stanza_t *message = xmpp_message_new(account->context,
                    channel->type == CHANNEL_TYPE_MUC
                    ? "groupchat" : "chat",
                    to, NULL);
    xmpp_message_set_body(message, body);

    char *url = strstr(body, "http");
    if (url)
    {
        xmpp_stanza_t *message__x = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(message__x, "x");
        xmpp_stanza_set_ns(message__x, "jabber:x:oob");

        xmpp_stanza_t *message__x__url = xmpp_stanza_new(account->context);
        xmpp_stanza_set_name(message__x__url, "url");

        xmpp_stanza_t *message__x__url__text = xmpp_stanza_new(account->context);
        xmpp_stanza_set_text(message__x__url__text, url);
        xmpp_stanza_add_child(message__x__url, message__x__url__text);
        xmpp_stanza_release(message__x__url__text);

        xmpp_stanza_add_child(message__x, message__x__url);
        xmpp_stanza_release(message__x__url);

        xmpp_stanza_add_child(message, message__x);
        xmpp_stanza_release(message__x);
    }

    xmpp_send(account->connection, message);
    xmpp_stanza_release(message);
    if (channel->type != CHANNEL_TYPE_MUC)
        weechat_printf(channel->buffer, "%s%s",
                       user__as_prefix_raw(account, account_jid(account)),
                       body);
}
