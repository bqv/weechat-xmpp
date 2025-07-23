// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <csignal>
#include <exception>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "config.hh"
#include "account.hh"
#include "connection.hh"
#include "command.hh"
#include "input.hh"
#include "buffer.hh"
#include "completion.hh"

#define WEECHAT_TIMER_INTERVAL_SEC 0.01
#define WEECHAT_TIMER_SECONDS(IVL) (WEECHAT_TIMER_INTERVAL_SEC * IVL)

#pragma GCC visibility push(default)
extern "C" {
WEECHAT_PLUGIN_NAME(WEECHAT_XMPP_PLUGIN_NAME);
WEECHAT_PLUGIN_DESCRIPTION(N_("XMPP client protocol"));
WEECHAT_PLUGIN_AUTHOR("bqv <weechat@fron.io>");
WEECHAT_PLUGIN_VERSION(WEECHAT_XMPP_PLUGIN_VERSION);
WEECHAT_PLUGIN_LICENSE("MPL2");
WEECHAT_PLUGIN_PRIORITY(5500);
}

void (* weechat_signal_handler)(int);

extern "C"
void wrapped_signal_handler(int arg)
{ // wrap weechat's handler
    weechat_signal_handler(arg);
    __asm__("int3");
}

extern "C"
int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
    try {
        weechat::plugin::instance = std::make_unique<weechat::plugin>(plugin);
        weechat::plugin::instance->init(argc, argv);
    }
    catch (std::exception const& ex) {
        return WEECHAT_RC_ERROR;
    }

    return WEECHAT_RC_OK;
}

extern "C"
int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
    try {
        if (plugin != *weechat::plugin::instance)
            throw std::runtime_error("wrong plugin?");
        weechat::plugin::instance->end();
        weechat::plugin::instance.reset();
    }
    catch (std::exception const& ex) {
        return WEECHAT_RC_ERROR;
    }

    return WEECHAT_RC_OK;
}

std::unique_ptr<weechat::plugin> weechat::plugin::instance;

weechat::plugin::plugin(struct t_weechat_plugin *plugin)
    : m_plugin_ptr(plugin)
{
}

void weechat::plugin::init(int argc, char *argv[])
{
    m_args = std::vector<std::string_view>(argv, argv+argc);

    if (std::find(m_args.begin(), m_args.end(), "debug") != m_args.end())
        weechat_signal_handler = std::signal(SIGSEGV, wrapped_signal_handler);

    if (!weechat::config::init()) // TODO: bool -> exceptions
        throw std::runtime_error("Config init failed");

    weechat::config::read();

    weechat::connection::init();

    command__init(); // TODO: port

    completion__init(); // TODO: port

    m_process_timer = weechat_hook_timer(WEECHAT_TIMER_SECONDS(1000), 0, 0,
                                         &weechat::account::timer_cb,
                                         nullptr, nullptr);

    if (!weechat_bar_search(typing_bar_name.data()))
    {
        weechat_bar_new(typing_bar_name.data(), "off", "400", "window", "${typing}",
                        "bottom", "horizontal", "vertical",
                        "1", "1", "default", "default", "default", "default",
                        "off", typing_bar_item_name.data());
    }

    m_typing_bar_item = weechat_bar_item_new(typing_bar_item_name.data(),
                                             &buffer__typing_bar_cb, // TODO: port
                                             nullptr, nullptr);

    weechat_hook_signal("input_text_changed",
                        &input__text_changed_cb, // TODO: port
                        nullptr, nullptr);
}

void weechat::plugin::end() {
    if (m_typing_bar_item) // raii?
        weechat_bar_item_remove(m_typing_bar_item);

    if (m_process_timer) // raii?
        weechat_unhook(m_process_timer);

    weechat::config::write();

    weechat::config::instance.reset();

    weechat::account::disconnect_all();

    weechat::accounts.clear();

    libstrophe::shutdown();
}

weechat::plugin::~plugin()
{
}
