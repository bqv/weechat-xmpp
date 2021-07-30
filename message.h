// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_MESSAGE_H_
#define _WEECHAT_XMPP_MESSAGE_H_

#define MESSAGE_MAX_LENGTH 40000

char *message__decode(struct t_account *account,
                           const char *text);

#endif /*WEECHAT_XMPP_MESSAGE_H*/
