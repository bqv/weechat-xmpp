// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <optional>
#include <string>
#include <tl/optional.hpp>

struct t_user_profile
{
    char *avatar_hash;
    char *status_text;
    char *status;
    tl::optional<std::string> idle;
    char *display_name;
    char *email;
    char *role;
    char *affiliation;
    char *pgp_id;
    int omemo;
};

struct t_user
{
    char *id;
    char *name;

    struct t_user_profile profile;
    int updated;
    int is_away;

    struct t_user *prev_user;
    struct t_user *next_user;
};

struct t_channel;

const char *user__get_colour(struct t_user *user);

const char *user__as_prefix_raw(struct t_account *account,
                                const char *name);

const char *user__as_prefix(struct t_account *account,
                            struct t_user *user,
                            const char *name);

struct t_user *user__search(struct t_account *account,
                            const char *id);

struct t_user *user__new(struct t_account *account,
                         const char *id, const char *display_name);

void user__free_all(struct t_account *account);

void user__nicklist_add(struct t_account *account,
                        struct t_channel *channel,
                        struct t_user *user);

void user__nicklist_remove(struct t_account *account,
                           struct t_channel *channel,
                           struct t_user *user);
