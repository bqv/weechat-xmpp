// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "account.h"
#include "user.h"
#include "channel.h"

const char *user__get_colour(struct t_user *user)
{
    return weechat_info_get("nick_color", user->profile.display_name);
}

const char *user__get_colour_for_nicklist(struct t_user *user)
{
    return weechat_info_get("nick_color_name", user->profile.display_name);
}

const char *user__as_prefix_raw(struct t_account *account,
                                const char *name)
{
    static char result[2048];

    (void) account;

    snprintf(result, sizeof(result), "%s%s\t",
             weechat_info_get("nick_color", name),
             name);

    return result;
}

const char *user__as_prefix(struct t_account *account,
                            struct t_user *user,
                            const char *name)
{
    static char result[2048];

    (void) account;

    snprintf(result, sizeof(result), "%s%s\t",
             user__get_colour(user),
             name ? name : user->profile.display_name);

    return result;
}

struct t_user *user__bot_search(struct t_account *account,
                                const char *bot_id)
{
    struct t_user *ptr_user;

    if (!account || !bot_id)
        return NULL;

    for (ptr_user = account->users; ptr_user;
         ptr_user = ptr_user->next_user)
    {
        if (ptr_user->profile.bot_id &&
            weechat_strcasecmp(ptr_user->profile.bot_id, bot_id) == 0)
            return ptr_user;
    }

    return NULL;
}

struct t_user *user__search(struct t_account *account,
                            const char *id)
{
    struct t_user *ptr_user;

    if (!account || !id)
        return NULL;

    for (ptr_user = account->users; ptr_user;
         ptr_user = ptr_user->next_user)
    {
        if (weechat_strcasecmp(ptr_user->id, id) == 0)
            return ptr_user;
    }

    return NULL;
}

void user__nicklist_add(struct t_account *account,
                        struct t_channel *channel,
                        struct t_user *user)
{
    struct t_gui_nick_group *ptr_group;
    struct t_gui_buffer *ptr_buffer;
    char *name = user->profile.display_name;
    if (channel && weechat_strcasecmp(xmpp_jid_bare(account->context, name),
                                      channel->id) == 0)
        name = xmpp_jid_resource(account->context, name);

    ptr_buffer = channel ? channel->buffer : account->buffer;

    ptr_group = weechat_nicklist_search_group(ptr_buffer, NULL,
                                              user->is_away ?
                                              "+" : "...");
    weechat_nicklist_add_nick(ptr_buffer, ptr_group,
                              name,
                              user->is_away ?
                              "weechat.color.nicklist_away" :
                              user__get_colour_for_nicklist(user),
                              user->is_away ? "+" : "",
                              "bar_fg",
                              1);
}

void user__nicklist_remove(struct t_account *account,
                           struct t_channel *channel,
                           struct t_user *user)
{
    struct t_gui_nick_group *ptr_group;
    struct t_gui_buffer *ptr_buffer;
    char *name = user->profile.display_name;
    if (channel && weechat_strcasecmp(xmpp_jid_bare(account->context, name),
                                      channel->id) == 0)
        name = xmpp_jid_resource(account->context, name);

    ptr_buffer = channel ? channel->buffer : account->buffer;

    ptr_group = weechat_nicklist_search_group(ptr_buffer, NULL,
                                              user->is_away ?
                                              "+" : "...");
    weechat_nicklist_remove_nick(ptr_buffer, 
        weechat_nicklist_search_nick(ptr_buffer, ptr_group, name));
}

struct t_user *user__new(struct t_account *account,
                         const char *id, const char *display_name)
{
    struct t_user *new_user, *ptr_user;

    if (!account || !id || !display_name)
    {
        return NULL;
    }

    if (!display_name[0] && strcmp("USLACKBOT", id) == 0)
        return NULL;

    if (!account->users)
        channel__add_nicklist_groups(account, NULL);

    ptr_user = user__search(account, id);
    if (ptr_user)
    {
        user__nicklist_add(account, NULL, ptr_user);
        return ptr_user;
    }

    if ((new_user = malloc(sizeof(*new_user))) == NULL)
    {
        return NULL;
    }

    new_user->prev_user = account->last_user;
    new_user->next_user = NULL;
    if (account->last_user)
        (account->last_user)->next_user = new_user;
    else
        account->users = new_user;
    account->last_user = new_user;

    new_user->id = strdup(id);
    new_user->name = NULL;
    new_user->team_id = NULL;
    new_user->real_name = NULL;
    new_user->colour = NULL;
    new_user->deleted = 0;

    new_user->tz = NULL;
    new_user->tz_label = NULL;
    new_user->tz_offset = 0;
    new_user->locale = NULL;

    new_user->profile.avatar_hash = NULL;
    new_user->profile.status_text = NULL;
    new_user->profile.status_emoji = NULL;
    new_user->profile.real_name = NULL;
    new_user->profile.display_name = display_name[0] ?
        strdup(display_name) :
        strdup("???");
    new_user->profile.real_name_normalized = NULL;
    new_user->profile.email = NULL;
    new_user->profile.team = NULL;
    new_user->profile.bot_id = NULL;
    new_user->updated = 0;
    new_user->is_away = 0;

    new_user->is_admin = 0;
    new_user->is_owner = 0;
    new_user->is_primary_owner = 0;
    new_user->is_restricted = 0;
    new_user->is_ultra_restricted = 0;
    new_user->is_bot = 0;
    new_user->is_stranger = 0;
    new_user->is_app_user = 0;
    new_user->has_2fa = 0;

    user__nicklist_add(account, NULL, new_user);

    return new_user;
}

void user__free(struct t_account *account,
                     struct t_user *user)
{
    struct t_user *new_users;

    if (!account || !user)
        return;

    /* remove user from users list */
    if (account->last_user == user)
        account->last_user = user->prev_user;
    if (user->prev_user)
    {
        (user->prev_user)->next_user = user->next_user;
        new_users = account->users;
    }
    else
        new_users = user->next_user;

    if (user->next_user)
        (user->next_user)->prev_user = user->prev_user;

    /* free user data */
    if (user->id)
        free(user->id);
    if (user->name)
        free(user->name);
    if (user->team_id)
        free(user->team_id);
    if (user->real_name)
        free(user->real_name);
    if (user->colour)
        free(user->colour);
    if (user->tz)
        free(user->tz);
    if (user->tz_label)
        free(user->tz_label);
    if (user->locale)
        free(user->locale);
    if (user->profile.avatar_hash)
        free(user->profile.avatar_hash);
    if (user->profile.status_text)
        free(user->profile.status_text);
    if (user->profile.status_emoji)
        free(user->profile.status_emoji);
    if (user->profile.real_name)
        free(user->profile.real_name);
    if (user->profile.display_name)
        free(user->profile.display_name);
    if (user->profile.real_name_normalized)
        free(user->profile.real_name_normalized);
    if (user->profile.email)
        free(user->profile.email);
    if (user->profile.team)
        free(user->profile.team);

    free(user);

    account->users = new_users;
}

void user__free_all(struct t_account *account)
{
    while (account->users)
        user__free(account, account->users);
}
