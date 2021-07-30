// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_CONFIG_H_
#define _WEECHAT_XMPP_CONFIG_H_

#define WEECHAT_XMPP_CONFIG_NAME "xmpp"

enum t_config_nick_completion
{
    CONFIG_NICK_COMPLETION_SMART_OFF = 0,
    CONFIG_NICK_COMPLETION_SMART_SPEAKERS,
    CONFIG_NICK_COMPLETION_SMART_SPEAKERS_HIGHLIGHTS,
};

extern struct t_config_file *config_file;

extern struct t_config_section *config_section_account_default;
extern struct t_config_section *config_section_account;

extern struct t_config_option *config_look_nick_completion_smart;

extern struct t_config_option *config_account_default[];

int config__account_check_value_cb(const void *pointer, void *data,
                                              struct t_config_option *option,
                                          const char *value);

void config__account_change_cb(const void *pointer, void *data,
                                      struct t_config_option *option);

struct t_config_option *config__account_new_option (struct t_config_file *config_file,
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

extern int config__init();
extern int config__read();
extern int config__write();
extern void config__free();

#endif /*WEECHAT_XMPP_CONFIG_H*/
