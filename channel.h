// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_CHANNEL_H_
#define _WEECHAT_XMPP_CHANNEL_H_

#define CHANNEL_MEMBERS_SPEAKING_LIMIT 128

enum t_channel_type
{
    CHANNEL_TYPE_MUC,
    CHANNEL_TYPE_PM,
};

struct t_channel_typing
{
    char *id;
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

struct t_channel
{
    enum t_channel_type type;
    char *id;
    char *name;

    struct t_channel_topic topic;

    /* mpim */
    char *creator;
    double last_read;
    int unread_count;
    int unread_count_display;

    struct t_hook *typing_hook_timer;
    struct t_weelist *members_speaking[2];
    struct t_channel_typing *typings;
    struct t_channel_typing *last_typing;
    struct t_channel_member *members;
    struct t_channel_member *last_member;
    struct t_gui_buffer *buffer;
    char *buffer_as_string;

    struct t_channel *prev_channel;
    struct t_channel *next_channel;
};

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

void channel__add_typing(struct t_channel *channel,
                         struct t_user *user);

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
                                             const char *id, const char *client,
                                             const char *status);

int channel__set_member_role(struct t_account *account,
                             struct t_channel *channel,
                             const char *id, const char *role);

int channel__set_member_affiliation(struct t_account *account,
                                    struct t_channel *channel,
                                    const char *id, const char *affiliation);

struct t_channel_member *channel__remove_member(struct t_account *account,
                                                struct t_channel *channel,
                                                const char *id, const char *status);

void channel__send_message(struct t_account *account, struct t_channel *channel,
                           const char *to, const char *body);

#endif /*WEECHAT_XMPP_CHANNEL_H*/
