// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_PLUGIN_H_
#define _WEECHAT_XMPP_PLUGIN_H_

#ifndef __cplusplus
#include <weechat/weechat-plugin.h>
#define weechat_plugin weechat_xmpp_plugin()
#define WEECHAT_XMPP_PLUGIN_NAME weechat_xmpp_plugin_name()
#define WEECHAT_XMPP_PLUGIN_VERSION weechat_xmpp_plugin_version()
#endif//__cplusplus

struct t_weechat_plugin *weechat_xmpp_plugin();
const char *weechat_xmpp_plugin_name();
const char *weechat_xmpp_plugin_version();

#endif /*WEECHAT_XMPP_PLUGIN_H*/
