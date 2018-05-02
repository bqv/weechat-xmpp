#ifndef _SLACK_USER_H_
#define _SLACK_USER_H_

struct t_slack_user_profile
{
    char *avatar_hash;
    char *status_text;
    char *status_emoji;
    char *real_name;
    char *display_name;
    char *real_name_normalized;
    char *email;
    char *team;
};

struct t_slack_user
{
    char *id;
    char *name;
    char *team_id;
    char *real_name;
    char *colour;

    int deleted;
    char *tz;
    char *tz_label;
    int tz_offset;
    char *locale;

    struct t_slack_user_profile profile;
    int updated;
    int is_away;

    int is_admin;
    int is_owner;
    int is_primary_owner;
    int is_restricted;
    int is_ultra_restricted;
    int is_bot;
    int is_stranger;
    int is_app_user;
    int has_2fa;

    struct t_slack_user *prev_user;
    struct t_slack_user *next_user;
};

struct t_slack_user *slack_user_search(struct t_slack_workspace *workspace,
                                       const char *id);

struct t_slack_user *slack_user_new(struct t_slack_workspace *workspace,
                                    const char *id, const char *display_name);

void slack_user_free_all(struct t_slack_workspace *workspace);

#endif /*SLACK_USER_H*/
