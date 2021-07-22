// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "account.h"
#include "config.h"

struct t_config_file *config_file;

struct t_config_section *config_section_account_default;
struct t_config_section *config_section_account;

struct t_config_option *config_look_nick_completion_smart;

struct t_config_option *config_account_default[ACCOUNT_NUM_OPTIONS];

int config__account_check_value_cb(const void *pointer, void *data,
                                  struct t_config_option *option,
                                  const char *value)
{
    (void) pointer;
    (void) data;
    (void) option;
    (void) value;

    return 1;
}

void config__account_change_cb(const void *pointer, void *data,
                              struct t_config_option *option)
{
    (void) pointer;
    (void) data;
    (void) option;
}

void config__account_default_change_cb(const void *pointer, void *data,
                                      struct t_config_option *option)
{
    (void) pointer;
    (void) data;
    (void) option;
}

struct t_config_option *
config__account_new_option (struct t_config_file *config_file,
                           struct t_config_section *section,
                           int index_option,
                           const char *option_name,
                           const char *default_value,
                           const char *value,
                           int null_value_allowed,
                           int (*callback_check_value)(const void *pointer,
                                                       void *data,
                                                       struct t_config_option *option,
                                                       const char *value),
                           const void *callback_check_value_pointer,
                           void *callback_check_value_data,
                           void (*callback_change)(const void *pointer,
                                                   void *data,
                                                   struct t_config_option *option),
                           const void *callback_change_pointer,
                           void *callback_change_data)
{
    struct t_config_option *new_option;

    new_option = NULL;

    switch (index_option)
    {
        case ACCOUNT_OPTION_JID:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account JID"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_PASSWORD:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account Password"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_TLS:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "integer",
                N_("XMPP Server TLS Policy"),
                "disable|normal|trust", 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_NICKNAME:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account Nickname"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_AUTOCONNECT:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "boolean",
                N_("Autoconnect XMPP Account"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_RESOURCE:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account Resource"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_STATUS:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account Login Status"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_PGP_PUBRING_PATH:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account PGP Public Keyring Path"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_OPTION_PGP_SECRING_PATH:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("XMPP Account PGP Secure Keyring Path"),
                NULL, 0, 0,
                default_value, value,
                null_value_allowed,
                callback_check_value,
                callback_check_value_pointer,
                callback_check_value_data,
                callback_change,
                callback_change_pointer,
                callback_change_data,
                NULL, NULL, NULL);
            break;
        case ACCOUNT_NUM_OPTIONS:
            break;
    }

    return new_option;
}

void config__account_create_default_options(struct t_config_section *section)
{
    int i;

    for (i = 0; i < ACCOUNT_NUM_OPTIONS; i++)
    {
        config_account_default[i] = config__account_new_option(
            config_file,
            section,
            i,
            account_options[i][0],
            account_options[i][1],
            account_options[i][1],
            0,
            &config__account_check_value_cb,
            account_options[i][0],
            NULL,
            &config__account_default_change_cb,
            account_options[i][0],
            NULL);
    }
}



int config__account_read_cb (const void *pointer, void *data,
                            struct t_config_file *config_file,
                            struct t_config_section *section,
                            const char *option_name, const char *value)
{
    struct t_account *ptr_account;
    int index_option, rc, i;
    char *pos_option, *account_name;

    (void) pointer;
    (void) data;
    (void) config_file;
    (void) section;

    rc = WEECHAT_CONFIG_OPTION_SET_ERROR;

    if (option_name)
    {
        pos_option = strrchr(option_name, '.');
        if (pos_option)
        {
            account_name = weechat_strndup(option_name,
                                           pos_option - option_name);
            pos_option++;
            if (account_name)
            {
                index_option = account__search_option(pos_option);
                if (index_option >= 0)
                {
                    ptr_account = account__search(account_name);
                    if (!ptr_account)
                        ptr_account = account__alloc(account_name);
                    if (ptr_account)
                    {
                        if (!ptr_account->reloading_from_config++)
                        {
                            for (i = 0; i < ACCOUNT_NUM_OPTIONS; i++)
                            {
                                weechat_config_option_set(
                                    ptr_account->options[i], NULL, 1);
                            }
                        }
                        ptr_account->reloading_from_config %=
                            ACCOUNT_NUM_OPTIONS;
                        rc = weechat_config_option_set(
                            ptr_account->options[index_option], value, 1);
                        if (!ptr_account->reloading_from_config)
                        {
                            const char *ac_global = weechat_info_get("auto_connect", NULL);
                            int ac_local = weechat_config_boolean(
                                ptr_account->options[ACCOUNT_OPTION_AUTOCONNECT]);
                            if (ac_local && (strcmp(ac_global, "1") == 0))
                                account__connect(ptr_account);
                        }
                    }
                    else
                    {
                        weechat_printf(
                            NULL,
                            _("%s%s: error adding account \"%s\""),
                            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
                            account_name);
                    }
                }
                free(account_name);
            }
        }
    }

    if (rc == WEECHAT_CONFIG_OPTION_SET_ERROR)
    {
        weechat_printf(
            NULL,
            _("%s%s: error creating account option \"%s\""),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME, option_name);
    }

    return rc;
}

int config__account_write_cb (const void *pointer, void *data,
                             struct t_config_file *config_file,
                             const char *section_name)
{
    struct t_account *ptr_account;
    int i;

    (void) pointer;
    (void) data;

    if (!weechat_config_write_line(config_file, section_name, NULL))
        return WEECHAT_CONFIG_WRITE_ERROR;

    for (ptr_account = accounts; ptr_account;
         ptr_account = ptr_account->next_account)
    {
        for (i = 0; i < ACCOUNT_NUM_OPTIONS; i++)
        {
            if (!weechat_config_write_option(config_file,
                                             ptr_account->options[i]))
                return WEECHAT_CONFIG_WRITE_ERROR;
        }
    }

    return WEECHAT_CONFIG_WRITE_OK;
}

int config__reload (const void *pointer, void *data,
                   struct t_config_file *config_file)
{
    (void) pointer;
    (void) data;

    weechat_config_section_free_options(config_section_account_default);
    weechat_config_section_free_options(config_section_account);
    account__free_all();

    return weechat_config_reload(config_file);
}

int config__init()
{
    struct t_config_section *ptr_section;

    config_file = weechat_config_new(WEECHAT_XMPP_CONFIG_NAME,
                                     &config__reload, NULL, NULL);

    if(!config_file)
        return 0;

    ptr_section = weechat_config_new_section(
        config_file, "look",
        0, 0,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL);

    if (!ptr_section)
    {
        weechat_config_free(config_file);
        config_file = NULL;
        return 0;
    }

    config_look_nick_completion_smart = weechat_config_new_option (
        config_file, ptr_section,
        "nick_completion_smart", "integer",
        N_("smart completion for nicks (completes first with last speakers): "
           "speakers = all speakers (including highlights), "
           "speakers_highlights = only speakers with highlight"),
        "off|speakers|speakers_highlights", 0, 0, "speakers", NULL, 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    ptr_section = weechat_config_new_section(
        config_file, "account_default",
        0, 0,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL);

    if (!ptr_section)
    {
        weechat_config_free(config_file);
        config_file = NULL;
        return 0;
    }

    config_section_account_default = ptr_section;

    config__account_create_default_options(ptr_section);

    ptr_section = weechat_config_new_section(
        config_file, "account",
        0, 0,
        &config__account_read_cb, NULL, NULL,
        &config__account_write_cb, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL);

    if (!ptr_section)
    {
        weechat_config_free(config_file);
        config_file = NULL;
        return 0;
    }

    config_section_account = ptr_section;

    return 1;
}

int config__read()
{
    int rc;

    rc = weechat_config_read(config_file);

    return rc;
}

int config__write()
{
    return weechat_config_write(config_file);
}

void config__free()
{
}
