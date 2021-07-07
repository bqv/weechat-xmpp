// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _ACCOUNT_H_
#define _ACCOUNT_H_

extern struct t_account *accounts;
extern struct t_account *last_account;

enum t_account_option
{
    ACCOUNT_OPTION_JID,
    ACCOUNT_OPTION_PASSWORD,
    ACCOUNT_OPTION_TLS,
    ACCOUNT_OPTION_NICKNAME,
    ACCOUNT_OPTION_AUTOCONNECT,
    ACCOUNT_OPTION_RESOURCE,
    ACCOUNT_OPTION_STATUS,
    ACCOUNT_NUM_OPTIONS,
};

#define account__option_string(account, option) \
    weechat_config_string(account->options[ACCOUNT_OPTION_ ## option])
#define account__option_integer(account, option) \
    weechat_config_integer(account->options[ACCOUNT_OPTION_ ## option])
#define account__option_boolean(account, option) \
    weechat_config_boolean(account->options[ACCOUNT_OPTION_ ## option])
#define account_option_set(account, option, value) \
    weechat_config_option_set(account->options[option], value, 1)

#define account_jid(account) \
    account->connection && xmpp_conn_is_connected(account->connection) ? \
        xmpp_jid_bare(account->context, xmpp_conn_get_bound_jid(account->connection)) : \
        weechat_config_string(account->options[ACCOUNT_OPTION_JID])
#define account_jid_device(account) \
    account->connection && xmpp_conn_is_connected(account->connection) ? \
        xmpp_conn_get_bound_jid(account->connection) : \
        xmpp_jid_new(account->context, \
                     xmpp_jid_node(account->context, \
                                   weechat_config_string(account->options[ACCOUNT_OPTION_JID])), \
                     xmpp_jid_domain(account->context, \
                                     weechat_config_string(account->options[ACCOUNT_OPTION_JID])), \
                     "weechat")
#define account_password(account) \
    weechat_config_string(account->options[ACCOUNT_OPTION_PASSWORD])
#define account_tls(account) \
    weechat_config_integer(account->options[ACCOUNT_OPTION_TLS])
#define account_nickname(account) \
    weechat_config_string(account->options[ACCOUNT_OPTION_NICKNAME])
#define account_autoconnect(account) \
    weechat_config_boolean(account->options[ACCOUNT_OPTION_AUTOCONNECT])
#define account_resource(account) \
    weechat_config_string(account->options[ACCOUNT_OPTION_RESOURCE])
#define account_status(account) \
    weechat_config_string(account->options[ACCOUNT_OPTION_STATUS])

struct t_device
{
    int id;
    char *name;

    struct t_device *prev_device;
    struct t_device *next_device;
};

struct t_account
{
    char *name;
    struct t_config_option *options[ACCOUNT_NUM_OPTIONS];

    int reloading_from_config;

    int is_connected;
    int disconnected;

    int current_retry;
    int reconnect_delay;
    int reconnect_start;

    xmpp_log_t logger;
    xmpp_ctx_t *context;
    xmpp_conn_t *connection;

    struct t_gui_buffer *buffer;
    char *buffer_as_string;

    struct t_omemo *omemo;

    struct t_device *devices;
    struct t_device *last_device;
    struct t_user *users;
    struct t_user *last_user;
    struct t_channel *channels;
    struct t_channel *last_channel;

    struct t_account *prev_account;
    struct t_account *next_account;
};

extern char *account_options[][2];

struct t_account *account__search(const char *account_name);
struct t_account *account__casesearch (const char *account_name);
int account__search_option(const char *option_name);
struct t_device *account__search_device(struct t_account *account, int id);
void account__add_device(struct t_account *account, struct t_device *device);
void account__free_device(struct t_account *account, struct t_device *device);
void account__free_device_all(struct t_account *account);
struct t_account *account__alloc(const char *name);
void account__free_data(struct t_account *account);
void account__free(struct t_account *account);
void account__free_all();
void account__disconnect(struct t_account *account, int reconnect);
void account__disconnect_all();
void account__close_connection(struct t_account *account);
int account__connect(struct t_account *account);
int account__timer_cb(const void *pointer, void *data, int remaining_calls);

#endif /*ACCOUNT_H*/
