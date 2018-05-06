#ifndef _SLACK_CHANNEL_H_
#define _SLACK_CHANNEL_H_

#define SLACK_CHANNEL_NAME_MAX_LEN 22

enum t_slack_channel_type
{
    SLACK_CHANNEL_TYPE_CHANNEL,
    SLACK_CHANNEL_TYPE_GROUP,
    SLACK_CHANNEL_TYPE_MPIM,
    SLACK_CHANNEL_TYPE_IM,
};

struct t_slack_channel_typing
{
    char *id;
    char *name;
    time_t ts;

    struct t_slack_channel_typing *prev_typing;
    struct t_slack_channel_typing *next_typing;
};

struct t_slack_channel_member
{
    char *id;

    struct t_slack_channel_member *prev_member;
    struct t_slack_channel_member *next_member;
};

struct t_slack_channel_topic
{
    char *value;
    char *creator;
    int last_set;
};

struct t_slack_channel_purpose
{
    char *value;
    char *creator;
    int last_set;
};

struct t_slack_channel
{
    enum t_slack_channel_type type; 
    char *id;
    char *name;
    int created;

    /* channel */
    int is_general;
    char *name_normalized;
    int is_shared;
    int is_org_shared;
    int is_member;

    /* group */
    struct t_slack_channel_topic topic;
    struct t_slack_channel_purpose purpose;
    int is_archived;

    /* mpim */
    char *creator;
    double last_read;
    int unread_count;
    int unread_count_display;

    /* im */
    int is_user_deleted;

    struct t_hook *typing_hook_timer;
    struct t_slack_channel_typing *typings;
    struct t_slack_channel_typing *last_typing;
    struct t_slack_channel_member *members;
    struct t_slack_channel_member *last_member;
    struct t_gui_buffer *buffer;
    char *buffer_as_string;

    struct t_slack_channel *prev_channel;
    struct t_slack_channel *next_channel;
};

struct t_slack_channel *slack_channel_search(struct t_slack_workspace *workspace,
                                             const char *id);

void slack_channel_add_nicklist_groups(struct t_slack_workspace *workspace,
                                       struct t_slack_channel *channel);

struct t_slack_channel *slack_channel_new(struct t_slack_workspace *workspace,
                                          enum t_slack_channel_type type,
                                          const char *id, const char *name);

void slack_channel_typing_free(struct t_slack_channel *channel,
                               struct t_slack_channel_typing *typing);

void slack_channel_typing_free_all(struct t_slack_channel *channel);

int slack_channel_typing_cb(const void *pointer,
                            void *data,
                            int remaining_calls);

struct t_slack_channel_typing *slack_channel_typing_search(
                                struct t_slack_channel *channel,
                                const char *id);

void slack_channel_add_typing(struct t_slack_channel *channel,
                              struct t_slack_user *user);

void slack_channel_free_all(struct t_slack_workspace *workspace);

#endif /*SLACK_CHANNEL_H*/
