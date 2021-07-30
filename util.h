// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_UTIL_H_
#define _WEECHAT_XMPP_UTIL_H_

int char_cmp(const void *p1, const void *p2);

char *exec(const char *command);

char *stanza_xml(struct _xmpp_stanza_t *stanza);

#endif /*WEECHAT_XMPP_UTIL_H*/
