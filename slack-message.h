#ifndef _SLACK_MESSAGE_H_
#define _SLACK_MESSAGE_H_

#define SLACK_MESSAGE_MAX_LENGTH 40000

char *slack_message_decode(struct t_slack_workspace *workspace,
                           const char *text);

#endif /*SLACK_MESSAGE_H*/
