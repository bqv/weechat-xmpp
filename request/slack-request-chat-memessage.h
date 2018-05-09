// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_REQUEST_CHAT_MEMESSAGE_H_
#define _SLACK_REQUEST_CHAT_MEMESSAGE_H_

struct t_slack_request *slack_request_chat_memessage(
                                   struct t_slack_workspace *workspace,
                                   const char *token, const char *channel,
                                   const char *text);

#endif /*SLACK_REQUEST_CHAT_MEMESSAGE_H*/
