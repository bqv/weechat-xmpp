#ifndef _SLACK_REQUEST_BOTS_INFO_H_
#define _SLACK_REQUEST_BOTS_INFO_H_

struct t_slack_request *slack_request_bots_info(
                                   struct t_slack_workspace *workspace,
                                   const char *token, const char *cursor);

#endif /*SLACK_REQUEST_BOTS_INFO_H*/
