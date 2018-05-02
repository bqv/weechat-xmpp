#ifndef _SLACK_API_H_
#define _SLACK_API_H_

void slack_api_init();

void slack_api_connect(struct t_slack_workspace *workspace);

int slack_api_route_message(struct t_slack_workspace *workspace,
                            const char *type, json_object *message);

#endif /*SLACK_API_H*/
