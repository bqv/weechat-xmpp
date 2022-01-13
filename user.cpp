// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "account.hh"
#include "user.hh"
#include "channel.hh"

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

    snprintf(result, sizeof(result), "%s%s%s",
             weechat_info_get("nick_color", name),
             name, weechat_color("reset"));

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
                                const char *pgp_id)
{
    struct t_user *ptr_user;

    if (!account || !pgp_id)
        return NULL;

    for (ptr_user = account->users; ptr_user;
         ptr_user = ptr_user->next_user)
    {
        if (ptr_user->profile.pgp_id &&
            weechat_strcasecmp(ptr_user->profile.pgp_id, pgp_id) == 0)
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
    char *name = channel ? user->profile.display_name : user->id;
    if (channel && weechat_strcasecmp(xmpp_jid_bare(account->context, name),
                                      channel->id) == 0)
        name = xmpp_jid_resource(account->context, name);

    ptr_buffer = channel ? channel->buffer : account->buffer;

    char *group = (char*)"...";
    if (weechat_strcasecmp(user->profile.affiliation, (char*)"outcast") == 0)
        group = (char*)"!";
    if (weechat_strcasecmp(user->profile.role, (char*)"visitor") == 0)
        group = (char*)"?";
    if (weechat_strcasecmp(user->profile.role, (char*)"participant") == 0)
        group = (char*)"+";
    if (weechat_strcasecmp(user->profile.affiliation, (char*)"member") == 0)
        group = (char*)"%";
    if (weechat_strcasecmp(user->profile.role, (char*)"moderator") == 0)
        group = (char*)"@";
    if (weechat_strcasecmp(user->profile.affiliation, (char*)"admin") == 0)
        group = (char*)"&";
    if (weechat_strcasecmp(user->profile.affiliation, (char*)"owner") == 0)
        group = (char*)"~";
    ptr_group = weechat_nicklist_search_group(ptr_buffer, NULL, group);
    weechat_nicklist_add_nick(ptr_buffer, ptr_group,
                              name,
                              user->is_away ?
                              "weechat.color.nicklist_away" :
                              user__get_colour_for_nicklist(user),
                              group,
                              "bar_fg",
                              1);
}

void user__nicklist_remove(struct t_account *account,
                           struct t_channel *channel,
                           struct t_user *user)
{
    struct t_gui_nick *ptr_nick;
    struct t_gui_buffer *ptr_buffer;
    char *name = user->profile.display_name;
    if (channel && weechat_strcasecmp(xmpp_jid_bare(account->context, name),
                                      channel->id) == 0)
        name = xmpp_jid_resource(account->context, name);

    ptr_buffer = channel ? channel->buffer : account->buffer;

    if (name && (ptr_nick = weechat_nicklist_search_nick(ptr_buffer, NULL, name)))
        weechat_nicklist_remove_nick(ptr_buffer, ptr_nick);
}

struct t_user *user__new(struct t_account *account,
                         const char *id, const char *display_name)
{
    struct t_user *new_user, *ptr_user;

    if (!account || !id)
    {
        return NULL;
    }

    if (!account->users)
        channel__add_nicklist_groups(account, NULL);

    ptr_user = user__search(account, id);
    if (ptr_user)
    {
        user__nicklist_add(account, NULL, ptr_user);
        return ptr_user;
    }

    if ((new_user = (struct t_user*)malloc(sizeof(*new_user))) == NULL)
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

    new_user->profile.avatar_hash = NULL;
    new_user->profile.status_text = NULL;
    new_user->profile.status = NULL;
    new_user->profile.idle = NULL;
    new_user->profile.display_name = display_name ?
        strdup(display_name) : strdup("");
    new_user->profile.affiliation = NULL;
    new_user->profile.email = NULL;
    new_user->profile.role = NULL;
    new_user->profile.pgp_id = NULL;
    new_user->profile.omemo = 0;
    new_user->updated = 0;
    new_user->is_away = 0;

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
    if (user->profile.avatar_hash)
        free(user->profile.avatar_hash);
    if (user->profile.status_text)
        free(user->profile.status_text);
    if (user->profile.status)
        free(user->profile.status);
    if (user->profile.idle)
        free(user->profile.idle);
    if (user->profile.display_name)
        free(user->profile.display_name);
    if (user->profile.affiliation)
        free(user->profile.affiliation);
    if (user->profile.email)
        free(user->profile.email);
    if (user->profile.role)
        free(user->profile.role);

    free(user);

    account->users = new_users;
}

void user__free_all(struct t_account *account)
{
    while (account->users)
        user__free(account, account->users);
}
