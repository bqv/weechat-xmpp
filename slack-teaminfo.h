#ifndef _SLACK_TEAMINFO_H_
#define _SLACK_TEAMINFO_H_

struct t_slack_teaminfo
{
    const char *id;
    const char *name;
    const char *domain;
    const char *email_domain;
    char *token;
};

extern void slack_teaminfo_fetch(char *token, void (*callback)(struct t_slack_teaminfo *slack_teaminfo));
extern void free_teaminfo(struct t_slack_teaminfo *teaminfo);

#endif /*SLACK_TEAMINFO_H*/
