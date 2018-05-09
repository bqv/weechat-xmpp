// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
