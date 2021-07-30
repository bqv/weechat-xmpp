// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <weechat/weechat-plugin.h>

#define weechat_plugin ::weechat::plugin::instance.get()

namespace weechat {
    extern "C" {
        //__attribute__((visibility("default")))
        int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[]);
        int weechat_plugin_end(struct t_weechat_plugin *plugin);
    }
    
    typedef std::unique_ptr<
        struct t_weechat_plugin,
        std::function<void(struct t_weechat_plugin *)>> plugin_ptr;

    class plugin : public plugin_ptr {
        public:
            plugin();
            plugin(plugin_ptr ptr);
            plugin(struct t_weechat_plugin *ptr);

            inline std::string const& name() const { return this->m_name; }
            inline std::string const& version() const { return this->m_version; }

            bool init(std::vector<std::string> args);
            bool end();

            static plugin instance;

        private:
            std::string m_name;
            std::string m_version;
    };
}
