// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <vector>
#include <string>

#include "strophe.hh"

#define STR(X) #X
#define XSTR(X) STR(X)

#define weechat_plugin (&*weechat::plugin::instance->ptr())
#define WEECHAT_XMPP_PLUGIN_NAME "xmpp"

#ifdef GIT_COMMIT
#define XMPP_PLUGIN_COMMIT XSTR(GIT_COMMIT)
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.1@" XMPP_PLUGIN_COMMIT
#else//GIT_COMMIT
#define XMPP_PLUGIN_COMMIT "unknown"
#define WEECHAT_XMPP_PLUGIN_VERSION "0.2.1"
#endif//GIT_COMMIT

namespace weechat {
    class plugin {
    private:
        struct t_weechat_plugin *m_plugin_ptr; // packed first for hackery

    public:
        plugin(struct t_weechat_plugin *plugin_ptr);
        virtual ~plugin();

        void init(int argc, char *argv[]);
        void end();

        static std::unique_ptr<plugin> instance;

        inline struct t_weechat_plugin * ptr() { return m_plugin_ptr; };
        inline operator struct t_weechat_plugin *() { return m_plugin_ptr; };

    private:
        static constexpr std::string_view typing_bar_name = "typing";
        static constexpr std::string_view typing_bar_item_name = "xmpp_typing";

        struct t_hook *m_process_timer;
        struct t_gui_bar_item *m_typing_bar_item;

        std::vector<std::string_view> m_args;
    };
};
