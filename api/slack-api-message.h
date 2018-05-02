#ifndef _SLACK_API_MESSAGE_H_
#define _SLACK_API_MESSAGE_H_

int slack_api_message(struct t_slack_workspace *workspace,
                      json_object *message);

void slack_api_message_init();

#endif /*SLACK_API_MESSAGE_H*/
