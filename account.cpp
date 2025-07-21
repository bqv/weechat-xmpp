// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fmt/core.h>
#include <libxml/xmlwriter.h>
#include <libxml/xmlerror.h>
#include <libxml/parser.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "xmpp/stanza.hh"
#include "config.hh"
#include "input.hh"
#include "omemo.hh"
#include "account.hh"
#include "connection.hh"
#include "user.hh"
#include "channel.hh"
#include "buffer.hh"

std::unordered_map<std::string, weechat::account> weechat::accounts;

void weechat::log_emit(void *const userdata, const xmpp_log_level_t level,
                       const char *const area, const char *const msg)
{
    auto account = static_cast<weechat::account*>(userdata);

    static const char *log_level_name[4] = {"debug", "info", "warn", "error"};

    const char *tags = level > XMPP_LEVEL_DEBUG ? "no_log" : NULL;

    char *xml;
    if ((level == XMPP_LEVEL_DEBUG) && ((xml = const_cast<char*>(strchr(msg, '<'))) != NULL))
    {
        FILE *nullfd = fopen("/dev/null", "w+");
        xmlGenericErrorContext = nullfd;

        const char *header = strndup(msg, xml - msg);
        xmlDocPtr doc = xmlRecoverMemory(xml, strlen(xml));
        if (doc == NULL) {
            weechat_printf(
                account ? account->buffer : NULL,
                "xml: Error parsing the xml document");
            fclose(nullfd);
            return;
        }
        xmlNodePtr root = xmlDocGetRootElement(doc);
        std::string tag = root ? (const char*)root->name : "";
        const char *colour = weechat_color("red");
        if (tag == "message")
        {
            colour = weechat_color("yellow");
        }
        else if (tag == "presence")
        {
            colour = weechat_color("green");
        }
        else if (tag == "iq")
        {
            colour = weechat_color("blue");
        }
        xmlChar *buf = (xmlChar*)malloc(strlen(xml) * 3);
        if (buf == NULL) {
            weechat_printf(
                account ? account->buffer : NULL,
                "xml: Error allocating the xml buffer");
            fclose(nullfd);
            return;
        }
        int size = -1;
        xmlDocDumpFormatMemory(doc, &buf, &size, 1);
        if (size <= 0) {
            weechat_printf(
                account ? account->buffer : NULL,
                "xml: Error formatting the xml document");
            fclose(nullfd);
            return;
        }
        char **lines = weechat_string_split((char*)buf, "\r\n", NULL,
                                            0, 0, &size);
        if (lines[size-1][0] == 0)
            lines[--size] = 0;
        weechat_printf_date_tags(
            account ? account->buffer : NULL,
            0, tags,
            _("%s%s (%s): %s"),
            weechat_prefix("network"), area,
            log_level_name[level], header);
        for (int i = 1; i < size; i++)
            weechat_printf_date_tags(
                account ? account->buffer : NULL,
                0, tags,
                _("%s%s"), colour, lines[i]);

        weechat_string_free_split(lines);
        fclose(nullfd);
    }
    else
    {
        weechat_printf_date_tags(
            account ? account->buffer : NULL,
            0, tags,
            _("%s%s (%s): %s"),
            weechat_prefix("network"), area,
            log_level_name[level], msg);
    }
}

bool weechat::account::search(weechat::account* &out,
                              const std::string name, bool casesensitive)
{
    if (name.empty())
        return false;

    if (casesensitive)
    {
        for (auto& account : weechat::accounts)
        {
            if (weechat_strcasecmp(account.second.name.data(), name.data()) == 0)
            {
                out = &account.second;
                return true;
            }
        }
    }
    else if (auto account = accounts.find(name); account != accounts.end())
    {
        out = &account->second;
        return true;
    }

    (void) out;
    return false;
}

bool weechat::account::search_device(weechat::account::device* out, std::uint32_t id)
{
    if (id == 0)
        return false;

    if (auto device = devices.find(id); device != devices.end())
    {
        out = &device->second;
        return true;
    }

    (void) out;
    return false;
}

void weechat::account::add_device(weechat::account::device *device)
{
    if (!devices.contains(device->id))
    {
        devices[device->id].id = device->id;
        devices[device->id].name = device->name;
        devices[device->id].label = device->label;
    }
}

void weechat::account::device_free_all()
{
    devices.clear();
}

xmpp_stanza_t *weechat::account::get_devicelist()
{
    int i = 0;

    account::device device;

    device.id = omemo.device_id;
    device.name = fmt::format("%u", device.id);
    device.label = "weechat";

    auto children = new xmpp_stanza_t*[128];
    children[i++] = stanza__iq_pubsub_publish_item_list_device(
        context, NULL, with_noop(device.name.data()), NULL);

    for (auto& device : devices)
    {
        if (device.first != omemo.device_id)
            children[i++] = stanza__iq_pubsub_publish_item_list_device(
                context, NULL, with_noop(device.second.name.data()), NULL);
    }

    children[i] = NULL;
    const char *node = "eu.siacs.conversations.axolotl";
    children[0] = stanza__iq_pubsub_publish_item_list(
        context, NULL, children, with_noop(node));
    children[1] = NULL;
    children[0] = stanza__iq_pubsub_publish_item(
        context, NULL, children, with_noop("current"));
    node = "eu.siacs.conversations.axolotl.devicelist";
    children[0] = stanza__iq_pubsub_publish(context, NULL, children, with_noop(node));
    const char *ns = "http://jabber.org/protocol/pubsub";
    children[0] = stanza__iq_pubsub(context, NULL, children, with_noop(ns));
    xmpp_stanza_t * parent = stanza__iq(context, NULL,
                                        children, NULL, strdup("announce1"),
                                        NULL, NULL, strdup("set"));
    delete[] children;

    return parent;
}

void weechat::account::add_mam_query(const std::string id, const std::string with,
                                     std::optional<time_t> start, std::optional<time_t> end)
{
    if (!mam_queries.contains(id))
    {
        mam_queries[id].id = id;
        mam_queries[id].with = with;

        mam_queries[id].start = start;
        mam_queries[id].end = end;
    }
}

bool weechat::account::mam_query_search(weechat::account::mam_query* out,
                                        const std::string id)
{
    if (id.empty())
        return false;

    if (auto mam_query = mam_queries.find(id); mam_query != mam_queries.end())
    {
        out = &mam_query->second;
        return true;
    }

    (void) out;
    return false;
}

void weechat::account::mam_query_remove(const std::string id)
{
    mam_queries.erase(id);
}

void weechat::account::mam_query_free_all()
{
    mam_queries.clear();
}

xmpp_log_t make_logger(void *userdata)
{
    xmpp_log_t logger = { nullptr };
    logger.handler = &weechat::log_emit;
    logger.userdata = userdata;
    return logger;
}

xmpp_mem_t make_memory(void *userdata)
{
    xmpp_mem_t memory = { nullptr };
    memory.alloc = [](const size_t size, void *const) {
        return calloc(1, size);
    };
    memory.free = [](void *ptr, void *const) {
        free(ptr);
    };
    memory.realloc = [](void *ptr, const size_t size, void *const) {
        return realloc(ptr, size);
    };
    memory.userdata = userdata;
    return memory;
}

weechat::account::account(config_file& config_file, const std::string name)
    : name(name), memory(make_memory(this)), logger(make_logger(this))
    , context(&memory, &logger), connection(*this, context)
    , config_account(config_file, config_file.configuration.section_account, name.data())
{
    if (account* result = nullptr; account::search(result, name))
        throw std::invalid_argument("account already exists");

    this->jid(config_file.configuration.account_default.option_jid.string().data());
    this->password(config_file.configuration.account_default.option_password.string().data());
    this->tls(config_file.configuration.account_default.option_tls.string().data());
    this->nickname(config_file.configuration.account_default.option_nickname.string().data());
    this->autoconnect(config_file.configuration.account_default.option_autoconnect.string().data());
    this->resource(config_file.configuration.account_default.option_resource.string().data());
    this->status(config_file.configuration.account_default.option_status.string().data());
    this->pgp_path(config_file.configuration.account_default.option_pgp_path.string().data());
    this->pgp_keyid(config_file.configuration.account_default.option_pgp_keyid.string().data());
}

weechat::account::~account()
{
    /*
     * close account buffer (and all channels/privates)
     * (only if we are not in a /upgrade, because during upgrade we want to
     * keep connections and closing account buffer would disconnect from account)
     */
    if (buffer)
        weechat_buffer_close(buffer);
}

void weechat::account::disconnect(int reconnect)
{
    if (is_connected)
    {
        /*
         * remove all nicks and write disconnection message on each
         * channel/private buffer
         */
      //user::free_all(this); // TOFIX
        weechat_nicklist_remove_all(buffer);
        for (auto& ptr_channel : channels)
        {
            weechat_nicklist_remove_all(ptr_channel.second.buffer);
            weechat_printf(
                ptr_channel.second.buffer,
                _("%s%s: disconnected from account"),
                weechat_prefix("network"), WEECHAT_XMPP_PLUGIN_NAME);
        }
        /* remove away status on account buffer */
        //weechat_buffer_set(buffer, "localvar_del_away", "");
    }

    reset();

    if (buffer)
    {
        weechat_printf(
            buffer,
            _("%s%s: disconnected from account"),
            weechat_prefix ("network"), WEECHAT_XMPP_PLUGIN_NAME);
    }

    if (reconnect)
    {
        if (current_retry++ == 0)
        {
            reconnect_delay = 5;
            reconnect_start = time(NULL) + reconnect_delay;
        }
        current_retry %= 5;
    }
    else
    {
        current_retry = 0;
        reconnect_delay = 0;
        reconnect_start = 0;
    }

    /*
    lag = 0;
    lag_displayed = -1;
    lag_check_time.tv_sec = 0;
    lag_check_time.tv_usec = 0;
    lag_next_check = time(NULL) +
        weechat_config_integer(xmpp_config_network_lag_check);
    lag_last_refresh = 0;
    account__set_lag(account);
    */ // lag based on xmpp ping

    disconnected = !reconnect;

    /* send signal "account_disconnected" with account name */
    (void) weechat_hook_signal_send("xmpp_account_disconnected",
                                    WEECHAT_HOOK_SIGNAL_STRING, name.data());
}

void weechat::account::disconnect_all()
{
    for (auto& account : accounts)
    {
        account.second.disconnect(0);
    }
}

struct t_gui_buffer *weechat::account::create_buffer()
{
    buffer = weechat_buffer_new(fmt::format("account.{}", name).data(),
                                &input__data_cb, NULL, NULL,
                                &buffer__close_cb, NULL, NULL);
    if (!buffer)
        return NULL;
    weechat_printf(buffer, "xmpp: %s", name.data());

    if (!weechat_buffer_get_integer(buffer, "short_name_is_set"))
        weechat_buffer_set(buffer, "short_name", name.data());
    weechat_buffer_set(buffer, "localvar_set_type", "server");
    weechat_buffer_set(buffer, "localvar_set_account", name.data());
    weechat_buffer_set(buffer, "localvar_set_charset_modifier",
                       fmt::format("account.{}", name).data());
    weechat_buffer_set(buffer, "title", name.data());

    weechat_buffer_set(buffer, "nicklist", "1");
    weechat_buffer_set(buffer, "nicklist_display_groups", "0");
    weechat_buffer_set_pointer(buffer, "nicklist_callback",
                               (void*)&buffer__nickcmp_cb);
    weechat_buffer_set_pointer(buffer, "nicklist_callback_pointer",
                               this);

    return buffer;
}

void weechat::account::reset()
{
    if (connection)
    {
        if (xmpp_conn_is_connected(connection))
            xmpp_disconnect(connection);
    }

    is_connected = 0;
}

int weechat::account::connect()
{
    if (!buffer)
    {
        if (!create_buffer())
            return 0;
        weechat_buffer_set(buffer, "display", "auto");
    }

    reset();

    is_connected = connection.connect(std::string(jid()), std::string(password()), tls());

    (void) weechat_hook_signal_send("xmpp_account_connecting",
                                    WEECHAT_HOOK_SIGNAL_STRING, name.data());

    return is_connected;
}

int weechat::account::timer_cb(const void *pointer, void *data, int remaining_calls)
{
    (void) pointer;
    (void) data;
    (void) remaining_calls;

  //try
    {
        if (accounts.empty()) return WEECHAT_RC_ERROR;

        for (auto& ptr_account : accounts)
        {
            if (ptr_account.second.is_connected
                && (xmpp_conn_is_connecting(ptr_account.second.connection)
                    || xmpp_conn_is_connected(ptr_account.second.connection)))
                ptr_account.second.connection.process(ptr_account.second.context, 10);
            else if (ptr_account.second.disconnected);
            else if (ptr_account.second.reconnect_start > 0
                     && ptr_account.second.reconnect_start < time(NULL))
            {
                ptr_account.second.connect();
            }
        }

        return WEECHAT_RC_OK;
    }
  //catch (const std::exception& ex)
  //{
  //    auto what = ex.what();
  //    __asm__("int3");
  //    return WEECHAT_RC_ERROR;
  //}
}
