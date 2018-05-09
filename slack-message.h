// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_MESSAGE_H_
#define _SLACK_MESSAGE_H_

#define SLACK_MESSAGE_MAX_LENGTH 40000

char *slack_message_decode(struct t_slack_workspace *workspace,
                           const char *text);

#endif /*SLACK_MESSAGE_H*/
