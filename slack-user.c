#include <stdlib.h>
#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-user.h"
#include "slack-channel.h"

struct t_slack_user *slack_user_search(struct t_slack_workspace *workspace,
                                       const char *id)
{
    struct t_slack_user *ptr_user;

    if (!workspace || !id)
        return NULL;

    for (ptr_user = workspace->users; ptr_user;
         ptr_user = ptr_user->next_user)
    {
        if (weechat_strcasecmp(ptr_user->id, id) == 0)
            return ptr_user;
    }

    return NULL;
}

void slack_user_nicklist_add(struct t_slack_workspace *workspace,
                             struct t_slack_channel *channel,
                             struct t_slack_user *user)
{
    struct t_gui_nick_group *ptr_group;
    struct t_gui_buffer *ptr_buffer;

    ptr_buffer = channel ? channel->buffer : workspace->buffer;

    ptr_group = weechat_nicklist_search_group(ptr_buffer, NULL,
                                              user->is_away ?
                                              "+" : "...");
    weechat_nicklist_add_nick(ptr_buffer, ptr_group,
                              user->profile.display_name,
                              weechat_color(user->is_away ? 
                                            "weechat.color.nicklist_away" :
                                            "bar_fg"),
                              user->is_away ? "+" : "",
                              weechat_color(""),
                              1);
}

struct t_slack_user *slack_user_new(struct t_slack_workspace *workspace,
                                    const char *id, const char *display_name)
{
    struct t_slack_user *new_user, *ptr_user;

    if (!workspace || !id || !display_name || !display_name[0])
        return NULL;

    if (!workspace->users)
        slack_channel_add_nicklist_groups(workspace, NULL);

    ptr_user = slack_user_search(workspace, id);
    if (ptr_user)
    {
        slack_user_nicklist_add(workspace, NULL, ptr_user);
        return ptr_user;
    }

    if ((new_user = malloc(sizeof(*new_user))) == NULL)
        return NULL;

    new_user->prev_user = workspace->last_user;
    new_user->next_user = NULL;
    if (workspace->last_user)
        (workspace->last_user)->next_user = new_user;
    else
        workspace->users = new_user;
    workspace->last_user = new_user;

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
    new_user->profile.display_name = strdup(display_name);
    new_user->profile.real_name_normalized = NULL;
    new_user->profile.email = NULL;
    new_user->profile.team = NULL;
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

    slack_user_nicklist_add(workspace, NULL, new_user);

    return new_user;
}

void slack_user_free(struct t_slack_workspace *workspace,
                     struct t_slack_user *user)
{
    struct t_slack_user *new_users;

    if (!workspace || !user)
        return;

	/* remove user from users list */
    if (workspace->last_user == user)
        workspace->last_user = user->prev_user;
    if (user->prev_user)
    {
        (user->prev_user)->next_user = user->next_user;
        new_users = workspace->users;
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

    workspace->users = new_users;
}

void slack_user_free_all(struct t_slack_workspace *workspace)
{
    while (workspace->users)
        slack_user_free(workspace, workspace->users);
}
