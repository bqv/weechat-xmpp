#ifndef _SLACK_API_ERROR_H_
#define _SLACK_API_ERROR_H_

int slack_api_error(struct t_slack_workspace *workspace,
                    json_object *message);

#endif /*SLACK_API_ERROR_H*/
