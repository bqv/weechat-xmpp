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

std::string weechat::user::get_colour()
{
    return weechat::user::get_colour(this->profile.display_name);
}

std::string weechat::user::get_colour(const char *name)
{
    return weechat_info_get("nick_color", name);
}

std::string weechat::user::get_colour_for_nicklist()
{
    return weechat::user::get_colour_for_nicklist(this->profile.display_name);
}

std::string weechat::user::get_colour_for_nicklist(const char *name)
{
    return weechat_info_get("nick_color_name", name);
}

std::string weechat::user::as_prefix_raw()
{
    return weechat::user::as_prefix_raw(this->profile.display_name);
}

std::string weechat::user::as_prefix_raw(const char *name)
{
    static char result[2048];

    snprintf(result, sizeof(result), "%s%s%s",
             weechat_info_get("nick_color", name),
             name, weechat_color("reset"));

    return result;
}

std::string weechat::user::as_prefix()
{
    return weechat::user::as_prefix(this->profile.display_name);
}

std::string weechat::user::as_prefix(const char *name)
{
    static char result[2048];

    snprintf(result, sizeof(result), "%s%s\t",
             weechat::user::get_colour(name).data(), name);

    return result;
}

weechat::user *weechat::user::bot_search(weechat::account *account,
                                         const char *pgp_id)
{
    if (!account || !pgp_id)
        return nullptr;

    for (auto& ptr_user : account->users)
    {
        if (ptr_user.second.profile.pgp_id &&
            ptr_user.second.profile.pgp_id == pgp_id)
            return &ptr_user.second;
    }

    return nullptr;
}

weechat::user *weechat::user::search(weechat::account *account,
                                     const char *id)
{
    if (!account || !id)
        return nullptr;

    if (auto user = account->users.find(id); user != account->users.end())
        return &user->second;

    return nullptr;
}

void weechat::user::nicklist_add(weechat::account *account,
                                 weechat::channel *channel)
{
    struct t_gui_nick_group *ptr_group;
    struct t_gui_buffer *ptr_buffer;
    char *name = channel ? this->profile.display_name : this->id;
    if (channel && weechat_strcasecmp(xmpp_jid_bare(account->context, name),
                                      channel->id.data()) == 0)
        name = xmpp_jid_resource(account->context, name);

    ptr_buffer = channel ? channel->buffer : account->buffer;

    char *group = (char*)"...";
    if (this->profile.affiliation ? this->profile.affiliation == std::string("outcast") : false)
        group = (char*)"!";
    if (this->profile.role ? this->profile.role == std::string("visitor") : false)
        group = (char*)"?";
    if (this->profile.role ? this->profile.role == std::string("participant") : false)
        group = (char*)"+";
    if (this->profile.affiliation ? this->profile.affiliation == std::string("member") : false)
        group = (char*)"%";
    if (this->profile.role ? this->profile.role == std::string("moderator") : false)
        group = (char*)"@";
    if (this->profile.affiliation ? this->profile.affiliation == std::string("admin") : false)
        group = (char*)"&";
    if (this->profile.affiliation ? this->profile.affiliation == std::string("owner") : false)
        group = (char*)"~";
    ptr_group = weechat_nicklist_search_group(ptr_buffer, nullptr, group);
    weechat_nicklist_add_nick(ptr_buffer, ptr_group,
                              name,
                              this->is_away ?
                              "weechat.color.nicklist_away" :
                              get_colour_for_nicklist().data(),
                              group,
                              "bar_fg",
                              1);
}

void weechat::user::nicklist_remove(weechat::account *account,
                                    weechat::channel *channel)
{
    struct t_gui_nick *ptr_nick;
    struct t_gui_buffer *ptr_buffer;
    char *name = this->profile.display_name;
    if (channel && weechat_strcasecmp(xmpp_jid_bare(account->context, name),
                                      channel->id.data()) == 0)
        name = xmpp_jid_resource(account->context, name);

    ptr_buffer = channel ? channel->buffer : account->buffer;

    if (name && (ptr_nick = weechat_nicklist_search_nick(ptr_buffer, nullptr, name)))
        weechat_nicklist_remove_nick(ptr_buffer, ptr_nick);
}

weechat::user::user(weechat::account *account,
                    const char *id, const char *display_name)
{
    if (!account || !id)
    {
        throw nullptr;
    }

  //if (account->users.empty())
  //    channel::add_nicklist_groups(account, nullptr);

    weechat::user *ptr_user = user::search(account, id);
    if (ptr_user)
    {
        throw nullptr;
    }

  //account->users += this;

    this->id = strdup(id);

    this->profile.display_name = display_name ?
        strdup(display_name) : strdup("");

    nicklist_add(account, nullptr);
}
