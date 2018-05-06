#ifndef _SLACK_API_USER_TYPING_H_
#define _SLACK_API_USER_TYPING_H_

int slack_api_user_typing(struct t_slack_workspace *workspace,
                          json_object *message);

#endif /*SLACK_API_USER_TYPING_H*/
