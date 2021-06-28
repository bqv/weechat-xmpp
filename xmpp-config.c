// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "xmpp.h"
#include "xmpp-config.h"

struct t_config_file *xmpp_config_file;

//struct t_config_section *xmpp_config_section_workspace_default;
//struct t_config_section *xmpp_config_section_workspace;

struct t_config_option *xmpp_config_server_jid;
struct t_config_option *xmpp_config_server_password;
struct t_config_option *xmpp_config_look_nick_completion_smart;

/*
struct t_config_option *xmpp_config_workspace_default[XMPP_WORKSPACE_NUM_OPTIONS];

int xmpp_config_workspace_check_value_cb(const void *pointer, void *data,
                                              struct t_config_option *option,
                                          const char *value)
{
    (void) pointer;
    (void) data;
    (void) option;
    (void) value;
        return 1;
}

void xmpp_config_workspace_change_cb(const void *pointer, void *data,
                                      struct t_config_option *option)
{
    (void) pointer;
    (void) data;
    (void) option;
}

void xmpp_config_workspace_default_change_cb(const void *pointer, void *data,
                                              struct t_config_option *option)
{
    (void) pointer;
    (void) data;
    (void) option;
}

struct t_config_option *
xmpp_config_workspace_new_option (struct t_config_file *config_file,
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
        case XMPP_WORKSPACE_OPTION_TOKEN:
            new_option = weechat_config_new_option (
                config_file, section,
                option_name, "string",
                N_("xmpp api token"),
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
                case XMPP_WORKSPACE_NUM_OPTIONS:
            break;
    }

    return new_option;
}

void xmpp_config_workspace_create_default_options(struct t_config_section *section)
{
    int i;

        for (i = 0; i < XMPP_WORKSPACE_NUM_OPTIONS; i++)
        {
                xmpp_config_workspace_default[i] = xmpp_config_workspace_new_option(
                        xmpp_config_file,
                        section,
                        i,
                        xmpp_workspace_options[i][0],
                        xmpp_workspace_options[i][1],
                        xmpp_workspace_options[i][1],
                        0,
                        &xmpp_config_workspace_check_value_cb,
                        xmpp_workspace_options[i][0],
                        NULL,
                        &xmpp_config_workspace_default_change_cb,
                        xmpp_workspace_options[i][0],
                        NULL);
        }
}



int xmpp_config_workspace_read_cb (const void *pointer, void *data,
                                    struct t_config_file *config_file,
                                    struct t_config_section *section,
                                    const char *option_name, const char *value)
{
    struct t_xmpp_workspace *ptr_workspace;
    int index_option, rc, i;
    char *pos_option, *workspace_domain;

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
            workspace_domain = weechat_strndup(option_name,
                                               pos_option - option_name);
            pos_option++;
            if (workspace_domain)
            {
                index_option = xmpp_workspace_search_option(pos_option);
                if (index_option >= 0)
                {
                    ptr_workspace = xmpp_workspace_search(workspace_domain);
                    if (!ptr_workspace)
                        ptr_workspace = xmpp_workspace_alloc(workspace_domain);
                    if (ptr_workspace)
                    {
                        if (ptr_workspace->reloading_from_config
                            && !ptr_workspace->reloaded_from_config)
                        {
                            for (i = 0; i < XMPP_WORKSPACE_NUM_OPTIONS; i++)
                            {
                                weechat_config_option_set(
                                    ptr_workspace->options[i], NULL, 1);
                            }
                            ptr_workspace->reloaded_from_config = 1;
                        }
                        rc = weechat_config_option_set(
                            ptr_workspace->options[index_option], value, 1);
                    }
                    else
                    {
                        weechat_printf(
                            NULL,
                            _("%s%s: error adding workspace \"%s\""),
                            weechat_prefix("error"), XMPP_PLUGIN_NAME,
                            workspace_domain);
                    }
                }
                free(workspace_domain);
            }
        }
    }

    if (rc == WEECHAT_CONFIG_OPTION_SET_ERROR)
    {
        weechat_printf(
            NULL,
            _("%s%s: error creating workspace option \"%s\""),
            weechat_prefix("error"), XMPP_PLUGIN_NAME, option_name);
    }

    return rc;
}

int xmpp_config_workspace_write_cb (const void *pointer, void *data,
                                     struct t_config_file *config_file,
                                     const char *section_name)
{
    struct t_xmpp_workspace *ptr_workspace;
    int i;

    (void) pointer;
    (void) data;

    if (!weechat_config_write_line(config_file, section_name, NULL))
        return WEECHAT_CONFIG_WRITE_ERROR;

    for (ptr_workspace = xmpp_workspaces; ptr_workspace;
         ptr_workspace = ptr_workspace->next_workspace)
    {
        for (i = 0; i < XMPP_WORKSPACE_NUM_OPTIONS; i++)
        {
            if (!weechat_config_write_option(config_file,
                                             ptr_workspace->options[i]))
                return WEECHAT_CONFIG_WRITE_ERROR;
        }
    }

    return WEECHAT_CONFIG_WRITE_OK;
}
*/

int xmpp_config_reload (const void *pointer, void *data,
                         struct t_config_file *config_file)
{
    (void) pointer;
    (void) data;

    //weechat_config_section_free_options(xmpp_config_section_workspace_default);
    //weechat_config_section_free_options(xmpp_config_section_workspace);
    //xmpp_workspace_free_all();

    return weechat_config_reload(config_file);
}

int xmpp_config_init()
{
    struct t_config_section *ptr_section_server;
    struct t_config_section *ptr_section_look;

    xmpp_config_file = weechat_config_new(XMPP_CONFIG_NAME,
                                           &xmpp_config_reload, NULL, NULL);

    if(!xmpp_config_file)
        return 0;

    ptr_section_server = weechat_config_new_section(
            xmpp_config_file, "server",
            0, 0,
            NULL, NULL, NULL,
            NULL, NULL, NULL,
            NULL, NULL, NULL,
            NULL, NULL, NULL,
            NULL, NULL, NULL);

    ptr_section_look = weechat_config_new_section(
            xmpp_config_file, "look",
            0, 0,
            NULL, NULL, NULL,
            NULL, NULL, NULL,
            NULL, NULL, NULL,
            NULL, NULL, NULL,
            NULL, NULL, NULL);

    if (!ptr_section_server
     || !ptr_section_server
     || !ptr_section_look)
    {
        weechat_config_free(xmpp_config_file);
        xmpp_config_file = NULL;
        return 0;
    }

    xmpp_config_server_jid = weechat_config_new_option (
        xmpp_config_file, ptr_section_server,
        "jid", "string",
        N_("XMPP Server JID"),
        NULL, 0, 0, "", "", 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    xmpp_config_server_password = weechat_config_new_option (
        xmpp_config_file, ptr_section_server,
        "password", "string",
        N_("XMPP Server Password"),
        NULL, 0, 0, "", "", 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    xmpp_config_look_nick_completion_smart = weechat_config_new_option (
        xmpp_config_file, ptr_section_look,
        "nick_completion_smart", "integer",
        N_("smart completion for nicks (completes first with last speakers): "
           "speakers = all speakers (including highlights), "
           "speakers_highlights = only speakers with highlight"),
        "off|speakers|speakers_highlights", 0, 0, "speakers", NULL, 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

  //ptr_section = weechat_config_new_section(
  //        xmpp_config_file, "workspace_default",
  //        0, 0,
  //        NULL, NULL, NULL,
  //        NULL, NULL, NULL,
  //        NULL, NULL, NULL,
  //        NULL, NULL, NULL,
  //        NULL, NULL, NULL);

  //if (!ptr_section)
  //{
  //    weechat_config_free(xmpp_config_file);
  //    xmpp_config_file = NULL;
  //    return 0;
  //}

  //xmpp_config_section_workspace_default = ptr_section;

  //xmpp_config_workspace_create_default_options(ptr_section);

  //    ptr_section = weechat_config_new_section(
  //    xmpp_config_file, "workspace",
  //    0, 0,
  //    &xmpp_config_workspace_read_cb, NULL, NULL,
  //    &xmpp_config_workspace_write_cb, NULL, NULL,
  //    NULL, NULL, NULL,
  //    NULL, NULL, NULL,
  //    NULL, NULL, NULL);

  //if (!ptr_section)
  //{
  //    weechat_config_free(xmpp_config_file);
  //    xmpp_config_file = NULL;
  //    return 0;
  //}

  //xmpp_config_section_workspace = ptr_section;

    return 1;
}

int xmpp_config_read()
{
        int rc;

    rc = weechat_config_read(xmpp_config_file);

    return rc;
}

int xmpp_config_write()
{
    return weechat_config_write(xmpp_config_file);
}

void xmpp_config_free()
{
}
