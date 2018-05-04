#ifndef _SLACK_REQUEST_CHAT_POSTMESSAGE_H_
#define _SLACK_REQUEST_CHAT_POSTMESSAGE_H_

struct t_slack_request *slack_request_chat_postmessage(
                                   struct t_slack_workspace *workspace,
                                   const char *token, const char *channel,
                                   const char *text);

#endif /*SLACK_REQUEST_CHAT_POSTMESSAGE_H*/
