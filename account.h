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
    ACCOUNT_NUM_OPTIONS,
};

struct t_account
{
    const char *name;
    struct t_config_option *options[ACCOUNT_NUM_OPTIONS];

    int reloading_from_config;

    int is_connected;
    int disconnected;

    xmpp_log_t logger;
    struct xmpp_ctx_t *context;
    struct xmpp_conn_t *connection;

    char *nickname;

    struct t_gui_buffer *buffer;
    char *buffer_as_string;
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
