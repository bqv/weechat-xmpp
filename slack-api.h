// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_API_H_
#define _SLACK_API_H_

void slack_api_init();

void slack_api_connect(struct t_slack_workspace *workspace);

int slack_api_route_message(struct t_slack_workspace *workspace,
                            const char *type, json_object *message);

#endif /*SLACK_API_H*/
