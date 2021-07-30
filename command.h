// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_COMMAND_H_
#define _WEECHAT_XMPP_COMMAND_H_

int command__enter(const void *pointer, void *data,
                   struct t_gui_buffer *buffer, int argc,
                   char **argv, char **argv_eol);
void command__init();

#endif /*WEECHAT_XMPP_COMMAND_H*/
