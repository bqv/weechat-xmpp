// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <ctime>

#define CHANNEL_MEMBERS_SPEAKING_LIMIT 128

enum t_channel_type
{
    CHANNEL_TYPE_MUC,
    CHANNEL_TYPE_PM,
};

enum t_channel_transport
{
    CHANNEL_TRANSPORT_PLAIN,
    CHANNEL_TRANSPORT_OMEMO,
    CHANNEL_TRANSPORT_PGP,
    CHANNEL_TRANSPORT_OTR,
    CHANNEL_TRANSPORT_OX,
};

struct t_channel_typing
{
    union {
        char *id;
        struct t_user *user;
    };
    char *name;
    time_t ts;

    struct t_channel_typing *prev_typing;
    struct t_channel_typing *next_typing;
};

struct t_channel_member
{
    char *id;

    char *role;
    char *affiliation;

    struct t_channel_member *prev_member;
    struct t_channel_member *next_member;
};

struct t_channel_topic
{
    char *value;
    char *creator;
    time_t last_set;
};

struct t_channel_unread
{
    char *id;
    char *thread;
};

struct t_channel
{
    enum t_channel_type type;
    char *id;
    char *name;
    enum t_channel_transport transport;
    struct {
        int enabled;
        struct t_hashtable *devicelist_requests;
        struct t_hashtable *bundle_requests;
    } omemo;
    struct {
        int enabled;
        char *id;
    } pgp;
    struct {
        int enabled;
    } otr;

    struct t_channel_topic topic;

    /* mpim */
    char *creator;
    double last_read;
    int unread_count;
    int unread_count_display;

    struct t_hook *typing_hook_timer;
    struct t_hook *self_typing_hook_timer;
    struct t_weelist *members_speaking[2];
    struct t_weelist *unreads;
    struct t_channel_typing *self_typings;
    struct t_channel_typing *last_self_typing;
    struct t_channel_typing *typings;
    struct t_channel_typing *last_typing;
    struct t_channel_member *members;
    struct t_channel_member *last_member;
    struct t_gui_buffer *buffer;
    char *buffer_as_string;

    struct t_channel *prev_channel;
    struct t_channel *next_channel;
};

const char *channel__transport_name(enum t_channel_transport transport);

void channel__set_transport(struct t_channel *channel,
                            enum t_channel_transport transport, int force);

struct t_account *channel__account(struct t_channel *channel);

struct t_channel *channel__search(struct t_account *account,
                                  const char *id);

void channel__add_nicklist_groups(struct t_account *account,
                                  struct t_channel *channel);

struct t_channel *channel__new(struct t_account *account,
                               enum t_channel_type type,
                               const char *id, const char *name);

void channel__member_speaking_add(struct t_channel *channel,
                                  const char *nick, int highlight);

void channel__member_speaking_rename(struct t_channel *channel,
                                     const char *old_nick,
                                     const char *new_nick);

void channel__member_speaking_rename_if_present(struct t_account *account,
                                                struct t_channel *channel,
                                                const char *nick);

void channel__typing_free(struct t_channel *channel,
                          struct t_channel_typing *typing);

void channel__typing_free_all(struct t_channel *channel);

int channel__typing_cb(const void *pointer,
                       void *data,
                       int remaining_calls);

struct t_channel_typing *channel__typing_search(struct t_channel *channel,
                                                const char *id);

int channel__add_typing(struct t_channel *channel,
                        struct t_user *user);

void channel__self_typing_free(struct t_channel *channel,
                               struct t_channel_typing *typing);

void channel__self_typing_free_all(struct t_channel *channel);

int channel__self_typing_cb(const void *pointer,
                            void *data,
                            int remaining_calls);

struct t_channel_typing *channel__self_typing_search(struct t_channel *channel,
                                                     struct t_user *user);

int channel__add_self_typing(struct t_channel *channel,
                             struct t_user *user);

int channel__hotlist_update_cb(const void *pointer, void *data,
                               const char *signal, const char *type_data,
                               void *signal_data);

void channel__unread_free(struct t_channel_unread *unread);

void channel__unread_free_all(struct t_channel *channel);

void channel__free(struct t_account *account,
                   struct t_channel *channel);

void channel__free_all(struct t_account *account);

void channel__update_topic(struct t_channel *channel,
                           const char* title,
                           const char* creator,
                           int last_set);

void channel__update_purpose(struct t_channel *channel,
                             const char* purpose,
                             const char* creator,
                             int last_set);

struct t_channel_member *channel__add_member(struct t_account *account,
                                             struct t_channel *channel,
                                             const char *id, const char *client);

struct t_channel_member *channel__member_search(struct t_channel *channel,
                                                const char *id);

struct t_channel_member *channel__remove_member(struct t_account *account,
                                                struct t_channel *channel,
                                                const char *id, const char *reason);

int channel__send_message(struct t_account *account, struct t_channel *channel,
                          const char *to, const char *body);

void channel__send_reads(struct t_account *account, struct t_channel *channel);

void channel__send_typing(struct t_account *account, struct t_channel *channel,
                          struct t_user *user);

void channel__send_paused(struct t_account *account, struct t_channel *channel,
                          struct t_user *user);

void channel__fetch_mam(struct t_account *account, struct t_channel *channel,
                        const char *id, time_t *start, time_t *end, const char *after);
