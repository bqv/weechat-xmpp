// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <libxml/xmlwriter.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "xmpp/stanza.hh"
#include "config.hh"
#include "input.h"
#include "omemo.hh"
#include "account.hh"
#include "connection.h"
#include "user.hh"
#include "channel.hh"
#include "buffer.h"

struct t_account *accounts = NULL;
struct t_account *last_account = NULL;

char *account_options[ACCOUNT_NUM_OPTIONS][2] =
{ { "jid", "" },
  { "password", "" },
  { "tls", "normal" },
  { "nickname", "" },
  { "autoconnect", "" },
  { "resource", "" },
  { "status", "probably about to segfault" },
  { "pgp_pubring_path", "${weechat_data_dir}/pubring.gpg" },
  { "pgp_secring_path", "${weechat_data_dir}/secring.gpg" },
  { "pgp_keyid", "" },
};

struct t_account *account__search(const char *name)
{
    struct t_account *ptr_account;

    if (!name)
        return NULL;

    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account->next_account)
    {
        if (strcmp(ptr_account->name, name) == 0)
            return ptr_account;
    }

    /* account not found */
    return NULL;
}

struct t_account *account__casesearch (const char *name)
{
    struct t_account *ptr_account;

    if (!name)
        return NULL;

    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account->next_account)
    {
        if (weechat_strcasecmp (ptr_account->name, name) == 0)
            return ptr_account;
    }

    /* account not found */
    return NULL;
}

int account__search_option(const char *option_name)
{
    int i;

    if (!option_name)
        return -1;

    for (i = 0; i < ACCOUNT_NUM_OPTIONS; i++)
    {
        if (weechat_strcasecmp(account_options[i][0], option_name) == 0)
            return i;
    }

    /* account option not found */
    return -1;
}

struct t_account_device *account__search_device(struct t_account *account, uint32_t id)
{
    struct t_account_device *ptr_device;

    if (!account)
        return NULL;

    for (ptr_device = account->devices; ptr_device;
         ptr_device = ptr_device->next_device)
    {
        if (ptr_device->id == id)
            return ptr_device;
    }

    return NULL;
}

void account__add_device(struct t_account *account,
                         struct t_account_device *device)
{
    struct t_account_device *new_device;

    new_device = account__search_device(account, device->id);
    if (!new_device)
    {
        new_device = (struct t_account_device*)malloc(sizeof(*new_device));
        new_device->id = device->id;
        new_device->name = strdup(device->name);
        new_device->label = device->label ? strdup(device->label) : NULL;

        new_device->prev_device = account->last_device;
        new_device->next_device = NULL;
        if (account->last_device)
            (account->last_device)->next_device = new_device;
        else
            account->devices = new_device;
        account->last_device = new_device;
    }
}

void account__free_device(struct t_account *account, struct t_account_device *device)
{
    struct t_account_device *new_devices;

    if (!account || !device)
        return;

    /* remove device from devices list */
    if (account->last_device == device)
        account->last_device = device->prev_device;
    if (device->prev_device)
    {
        (device->prev_device)->next_device = device->next_device;
        new_devices = account->devices;
    }
    else
        new_devices = device->next_device;

    if (device->next_device)
        (device->next_device)->prev_device = device->prev_device;

    /* free device data */
    if (device->label)
        free(device->label);
    if (device->name)
        free(device->name);

    free(device);

    account->devices = new_devices;
}

void account__free_device_all(struct t_account *account)
{
    while (account->devices)
        account__free_device(account, account->devices);
}

xmpp_stanza_t *account__get_devicelist(struct t_account *account)
{
    xmpp_stanza_t *parent, **children;
    struct t_account_device *device;
    const char *ns, *node;
    char id[64] = {0};
    int i = 0;

    device = (struct t_account_device*)malloc(sizeof(struct t_account_device));

    device->id = account->omemo->device_id;
    snprintf(id, sizeof(id), "%u", device->id);
    device->name = strdup(id);
    device->label = strdup("weechat");

    children = (xmpp_stanza_t **)malloc(sizeof(xmpp_stanza_t *) * 128);
    children[i++] = stanza__iq_pubsub_publish_item_list_device(
        account->context, NULL, with_noop(device->name), NULL);

    free(device->label);
    free(device->name);
    free(device);

    for (device = account->devices; device;
         device = device->next_device)
    {
        if (device->id != account->omemo->device_id)
            children[i++] = stanza__iq_pubsub_publish_item_list_device(
                account->context, NULL, with_noop(device->name), NULL);
    }

    children[i] = NULL;
    node = "eu.siacs.conversations.axolotl";
    children[0] = stanza__iq_pubsub_publish_item_list(
        account->context, NULL, children, with_noop(node));
    children[1] = NULL;
    children[0] = stanza__iq_pubsub_publish_item(
        account->context, NULL, children, with_noop("current"));
    node = "eu.siacs.conversations.axolotl.devicelist";
    children[0] = stanza__iq_pubsub_publish(account->context,
                                            NULL, children,
                                            with_noop(node));
    ns = "http://jabber.org/protocol/pubsub";
    children[0] = stanza__iq_pubsub(account->context, NULL,
                                    children, with_noop(ns));
    parent = stanza__iq(account->context, NULL,
                        children, NULL, strdup("announce1"),
                        NULL, NULL, strdup("set"));
    free(children);

    return parent;
}

struct t_account_mam_query *account__add_mam_query(struct t_account *account,
                                                   struct t_channel *channel,
                                                   const char *id,
                                                   time_t *start, time_t *end)
{
    struct t_account_mam_query *mam_query;

    if (!(mam_query = account__mam_query_search(account, id)))
    {
        mam_query = (struct t_account_mam_query*)malloc(sizeof(struct t_account_mam_query));
        mam_query->id = strdup(id);
        mam_query->with = strdup(channel->id);

        mam_query->has_start = start != NULL;
        if (mam_query->has_start)
            mam_query->start = *start;
        mam_query->has_end = end != NULL;
        if (mam_query->has_end)
            mam_query->end = *end;

        mam_query->prev_mam_query = account->last_mam_query;
        mam_query->next_mam_query = NULL;
        if (account->last_mam_query)
            (account->last_mam_query)->next_mam_query = mam_query;
        else
            account->mam_queries = mam_query;
        account->last_mam_query = mam_query;
    }

    return mam_query;
}

struct t_account_mam_query *account__mam_query_search(struct t_account *account,
                                                      const char *id)
{
    struct t_account_mam_query *ptr_mam_query;

    if (!account || !id)
        return NULL;

    for (ptr_mam_query = account->mam_queries; ptr_mam_query;
         ptr_mam_query = ptr_mam_query->next_mam_query)
    {
        if (weechat_strcasecmp(ptr_mam_query->id, id) == 0)
            return ptr_mam_query;
    }

    return NULL;
}

void account__mam_query_free(struct t_account *account,
                             struct t_account_mam_query *mam_query)
{
    struct t_account_mam_query *new_mam_queries;

    if (!account || !mam_query)
        return;

    /* remove mam_query from mam_queries list */
    if (account->last_mam_query == mam_query)
        account->last_mam_query = mam_query->prev_mam_query;
    if (mam_query->prev_mam_query)
    {
        (mam_query->prev_mam_query)->next_mam_query = mam_query->next_mam_query;
        new_mam_queries = account->mam_queries;
    }
    else
        new_mam_queries = mam_query->next_mam_query;

    if (mam_query->next_mam_query)
        (mam_query->next_mam_query)->prev_mam_query = mam_query->prev_mam_query;

    /* free mam_query data */
    if (mam_query->id)
        free(mam_query->id);
    if (mam_query->with)
        free(mam_query->with);

    free(mam_query);

    account->mam_queries = new_mam_queries;
}

void account__mam_query_free_all(struct t_account *account)
{
    while (account->mam_queries)
        account__mam_query_free(account, account->mam_queries);
}

void account__log_emit_weechat(void *const userdata, const xmpp_log_level_t level,
                               const char *const area, const char *const msg)
{
    struct t_account *account = (struct t_account*)userdata;

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
        const char *tag = root ? (const char*)root->name : "";
        const char *colour = weechat_color("blue");
        if (weechat_strcasecmp(tag, "message"))
        {
            colour = weechat_color("green");
        }
        else if (weechat_strcasecmp(tag, "presence"))
        {
            colour = weechat_color("yellow");
        }
        else if (weechat_strcasecmp(tag, "iq"))
        {
            colour = weechat_color("red");
        }
        xmlChar *buf = (xmlChar*)malloc(strlen(xml) * 2);
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

struct t_account *account__alloc(const char *name)
{
    struct t_account *new_account;
    int i, length;
    char *option_name;

    if (account__casesearch(name))
        return NULL;

    /* alloc memory for new account */
    new_account = (struct t_account*)malloc(sizeof(*new_account));
    if (!new_account)
    {
        weechat_printf(NULL,
                       _("%s%s: error when allocating new account"),
                       weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return NULL;
    }

    /* add new account to queue */
    new_account->prev_account = last_account;
    new_account->next_account = NULL;
    if (last_account)
        last_account->next_account = new_account;
    else
        accounts = new_account;
    last_account = new_account;

    /* set name */
    new_account->name = strdup(name);

    /* internal vars */
    new_account->reloading_from_config = 0;

    new_account->is_connected = 0;
    new_account->disconnected = 0;

    new_account->current_retry = 0;
    new_account->reconnect_delay = 0;
    new_account->reconnect_start = 0;

    new_account->logger.handler = &account__log_emit_weechat;
    new_account->logger.userdata = new_account;
    new_account->context = xmpp_ctx_new(NULL, &new_account->logger);
    new_account->connection = NULL;

    new_account->buffer = NULL;
    new_account->buffer_as_string = NULL;

    new_account->omemo = NULL;

    new_account->devices = NULL;
    new_account->last_device = NULL;
    new_account->mam_queries = NULL;
    new_account->last_mam_query = NULL;
    new_account->users = NULL;
    new_account->last_user = NULL;
    new_account->channels = NULL;
    new_account->last_channel = NULL;

    /* create options with null value */
    for (i = 0; i < ACCOUNT_NUM_OPTIONS; i++)
    {
        new_account->options[i] = NULL;

        length = strlen(new_account->name) + 1 +
            strlen(account_options[i][0]) +
            512 +  /* inherited option name(xmpp.account_default.xxx) */
            1;
        option_name = (char*)malloc(length);
        if (option_name)
        {
            snprintf(option_name, length, "%s.%s << xmpp.account_default.%s",
                     new_account->name,
                     account_options[i][0],
                     account_options[i][0]);
            new_account->options[i] = config__account_new_option(
                config_file,
                config_section_account,
                i,
                option_name,
                account_options[i][1],
                account_options[i][1],
                0,
                &config__account_check_value_cb,
                account_options[i][0],
                NULL,
                &config__account_change_cb,
                account_options[i][0],
                NULL);
            config__account_change_cb(account_options[i][0], NULL,
                                      new_account->options[i]);
            free(option_name);
        }
    }

    return new_account;
}

void account__free_data(struct t_account *account)
{
  //int i;

    if (!account)
        return;

    /* free linked lists */
    /*
    for (i = 0; i < IRC_SERVER_NUM_OUTQUEUES_PRIO; i++)
    {
        account__outqueue_free_all(account, i);
    }
    xmpp_redirect_free_all(account);
    xmpp_notify_free_all(account);
    */
    account__free_device_all(account);
    account__mam_query_free_all(account);
    channel__free_all(account);
    user__free_all(account);

    /* free hashtables */
    /*
    weechat_hashtable_free(account->join_manual);
    weechat_hashtable_free(account->join_channel_key);
    weechat_hashtable_free(account->join_noswitch);
    */

    /* close xmpp context */
    if (account->connection)
        xmpp_conn_release(account->connection);
    if (account->context)
        xmpp_ctx_free(account->context);

    /* free account data */
  //for (i = 0; i < ACCOUNT_NUM_OPTIONS; i++)
  //{
  //    if (account->options[i])
  //        weechat_config_option_free(account->options[i]);
  //}

    if (account->name)
        free(account->name);

    if (account->buffer_as_string)
        free(account->buffer_as_string);

    if (account->omemo)
        omemo__free(account->omemo);

  //channel__free_all(account);
  //user__free_all(account);
}

void account__free(struct t_account *account)
{
    struct t_account *new_accounts;

    if (!account)
        return;

    /*
     * close account buffer (and all channels/privates)
     * (only if we are not in a /upgrade, because during upgrade we want to
     * keep connections and closing account buffer would disconnect from account)
     */
    if (account->buffer)
        weechat_buffer_close(account->buffer);

    /* remove account from queue */
    if (last_account == account)
        last_account = account->prev_account;
    if (account->prev_account)
    {
        (account->prev_account)->next_account = account->next_account;
        new_accounts = accounts;
    }
    else
        new_accounts = account->next_account;

    if (account->next_account)
        (account->next_account)->prev_account = account->prev_account;

    account__free_data(account);
    free(account);
    accounts = new_accounts;
}

void account__free_all()
{
    /* for each account in memory, remove it */
    while (accounts)
    {
        account__free(accounts);
    }
}

void account__disconnect(struct t_account *account, int reconnect)
{
    (void) reconnect;

    struct t_channel *ptr_channel;

    if (account->is_connected)
    {
        /*
         * remove all nicks and write disconnection message on each
         * channel/private buffer
         */
        user__free_all(account);
        weechat_nicklist_remove_all(account->buffer);
        for (ptr_channel = account->channels; ptr_channel;
             ptr_channel = ptr_channel->next_channel)
        {
            weechat_nicklist_remove_all(ptr_channel->buffer);
            weechat_printf(
                ptr_channel->buffer,
                _("%s%s: disconnected from account"),
                weechat_prefix("network"), WEECHAT_XMPP_PLUGIN_NAME);
        }
        /* remove away status on account buffer */
        //weechat_buffer_set(account->buffer, "localvar_del_away", "");
    }

    account__close_connection(account);

    if (account->buffer)
    {
        weechat_printf(
            account->buffer,
            _("%s%s: disconnected from account"),
            weechat_prefix ("network"), WEECHAT_XMPP_PLUGIN_NAME);
    }

    if (reconnect)
    {
        if (account->current_retry++ == 0)
        {
            account->reconnect_delay = 5;
            account->reconnect_start = time(NULL) + account->reconnect_delay;
        }
        account->current_retry %= 5;
    }
    else
    {
        account->current_retry = 0;
        account->reconnect_delay = 0;
        account->reconnect_start = 0;
    }

    /*
    account->lag = 0;
    account->lag_displayed = -1;
    account->lag_check_time.tv_sec = 0;
    account->lag_check_time.tv_usec = 0;
    account->lag_next_check = time(NULL) +
        weechat_config_integer(xmpp_config_network_lag_check);
    account->lag_last_refresh = 0;
    account__set_lag(account);
    */ // lag based on xmpp ping

    account->disconnected = !reconnect;

    /* send signal "account_disconnected" with account name */
    (void) weechat_hook_signal_send("xmpp_account_disconnected",
                                    WEECHAT_HOOK_SIGNAL_STRING, account->name);
}

void account__disconnect_all()
{
    struct t_account *ptr_account;

    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account->next_account)
    {
        account__disconnect(ptr_account, 0);
    }
}

struct t_gui_buffer *account__create_buffer(struct t_account *account)
{
    char buffer_name[256], charset_modifier[256];

    snprintf(buffer_name, sizeof(buffer_name),
             "account.%s", account->name);
    account->buffer = weechat_buffer_new(buffer_name,
                                         &input__data_cb, NULL, NULL,
                                         &buffer__close_cb, NULL, NULL);
    if (!account->buffer)
        return NULL;

    if (!weechat_buffer_get_integer(account->buffer, "short_name_is_set"))
        weechat_buffer_set(account->buffer, "short_name", account->name);
    weechat_buffer_set(account->buffer, "localvar_set_type", "server");
    weechat_buffer_set(account->buffer, "localvar_set_server", account->name);
    weechat_buffer_set(account->buffer, "localvar_set_channel", account->name);
    snprintf(charset_modifier, sizeof (charset_modifier),
             "account.%s", account->name);
    weechat_buffer_set(account->buffer, "localvar_set_charset_modifier",
                       charset_modifier);
    weechat_buffer_set(account->buffer, "title",
                       (account->name) ? account->name : "");

    weechat_buffer_set(account->buffer, "nicklist", "1");
    weechat_buffer_set(account->buffer, "nicklist_display_groups", "0");
    weechat_buffer_set_pointer(account->buffer, "nicklist_callback",
                               (void*)&buffer__nickcmp_cb);
    weechat_buffer_set_pointer(account->buffer, "nicklist_callback_pointer",
                               account);

    return account->buffer;
}

void account__close_connection(struct t_account *account)
{
    if (account->connection)
    {
        if (xmpp_conn_is_connected(account->connection))
            xmpp_disconnect(account->connection);
    }

    account->is_connected = 0;
}

int account__connect(struct t_account *account)
{
    if (!account->buffer)
    {
        if (!account__create_buffer(account))
            return 0;
        weechat_buffer_set(account->buffer, "display", "auto");
    }

    account__close_connection(account);

    account->is_connected =
        connection__connect(account, &account->connection, account_jid(account),
                            account_password(account), account_tls(account));

    (void) weechat_hook_signal_send("xmpp_account_connecting",
                                    WEECHAT_HOOK_SIGNAL_STRING, account->name);

    return account->is_connected;
}

int account__timer_cb(const void *pointer, void *data, int remaining_calls)
{
    (void) pointer;
    (void) data;
    (void) remaining_calls;

    struct t_account *ptr_account;

    if (!accounts) return WEECHAT_RC_ERROR;

    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account ? ptr_account->next_account : NULL)
    {
        if (ptr_account->is_connected
            && (xmpp_conn_is_connecting(ptr_account->connection)
                || xmpp_conn_is_connected(ptr_account->connection)))
            connection__process(ptr_account->context, ptr_account->connection, 10);
        else if (ptr_account->disconnected);
        else if (ptr_account->reconnect_start > 0
                 && ptr_account->reconnect_start < time(NULL))
        {
            account__connect(ptr_account);
        }
    }

    return WEECHAT_RC_OK;
}
