// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

namespace c {
    extern "C" {
#include "plugin.h"
// #include "connection.h"
        void connection__init() { return; }
        bool connection__connect(weechat::xmpp::account&, xmpp::connection&,
                                 std::string, std::string, std::string) { return true; }
        void connection__process(xmpp::context&, xmpp::connection&, int) { return; }
// #include "command.h"
        void command__init() { return; }
// #include "input.h"
        int input__text_changed_cb(const void*, void*, const char*, const char*, void*) { return 0; }
// #include "buffer.h"
        std::string buffer__typing_bar_cb(weechat::gui_bar_item&, weechat::gui_window&,
                                          weechat::gui_buffer&, weechat::hashtable&) { return ""; }
        int buffer__close_cb(const void*, void*, struct t_gui_buffer*) { return 0; }
        int buffer__nickcmp_cb(struct t_gui_buffer*, const char*, const char*) { return 0; }
// #include "completion.h"
        void completion__init() { return; }
// #include "user.h"
        void user__free_all(weechat::xmpp::account&) { return; }
    }
}

struct weechat::xmpp::t_channel {
    weechat::gui_buffer buffer;
};
