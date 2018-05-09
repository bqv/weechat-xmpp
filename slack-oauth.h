// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_OAUTH_H_
#define _SLACK_OAUTH_H_

extern void slack_oauth_request_token(char *code, void (*callback)(char *token));

#endif /*SLACK_OAUTH_H*/
