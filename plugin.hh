// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#define STR(X) #X
#define XSTR(X) STR(X)
#define weechat_plugin weechat_xmpp_plugin
#define WEECHAT_XMPP_PLUGIN_NAME "xmpp"
#ifdef GIT_COMMIT
#define XMPP_PLUGIN_COMMIT XSTR(GIT_COMMIT)
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.0@" XMPP_PLUGIN_COMMIT
#else//GIT_COMMIT
#define XMPP_PLUGIN_COMMIT "unknown"
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.0"
#endif//GIT_COMMIT
#define TIMER_INTERVAL_SEC 0.01

extern struct t_weechat_plugin *weechat_xmpp_plugin;
