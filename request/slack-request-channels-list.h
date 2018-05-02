#ifndef _SLACK_REQUEST_CHANNELS_LIST_H_
#define _SLACK_REQUEST_CHANNELS_LIST_H_

struct t_slack_request *slack_request_channels_list(
                                   struct t_slack_workspace *workspace,
                                   const char *token, const char *cursor);

#endif /*SLACK_REQUEST_CHANNELS_LIST_H*/
