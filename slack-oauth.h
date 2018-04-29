#ifndef _SLACK_OAUTH_H_
#define _SLACK_OAUTH_H_

extern void slack_oauth_request_token(char *code, void (*callback)(char *token));

#endif /*SLACK_OAUTH_H*/
