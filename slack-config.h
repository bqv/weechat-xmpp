// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_CONFIG_H_
#define _SLACK_CONFIG_H_

#define SLACK_CONFIG_NAME "slack"

enum t_slack_config_nick_completion
{
    SLACK_CONFIG_NICK_COMPLETION_SMART_OFF = 0,
    SLACK_CONFIG_NICK_COMPLETION_SMART_SPEAKERS,
    SLACK_CONFIG_NICK_COMPLETION_SMART_SPEAKERS_HIGHLIGHTS,
};

extern struct t_config_file *slack_config_file;

extern struct t_config_section *slack_config_section_workspace_default;
extern struct t_config_section *slack_config_section_workspace;

extern struct t_config_option *slack_config_look_nick_completion_smart;

extern struct t_config_option *slack_config_workspace_default[];

int slack_config_workspace_check_value_cb(const void *pointer, void *data,
   	                                      struct t_config_option *option,
                                          const char *value);

void slack_config_workspace_change_cb(const void *pointer, void *data,
                                      struct t_config_option *option);

struct t_config_option *slack_config_workspace_new_option (struct t_config_file *config_file,
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
                                                           void *callback_change_data);

extern int slack_config_init();
extern int slack_config_read();
extern int slack_config_write();
extern void slack_config_free();

#endif /*SLACK_CONFIG_H*/
