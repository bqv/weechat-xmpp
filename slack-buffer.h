// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_BUFFER_H_
#define _SLACK_BUFFER_H_

void slack_buffer_get_workspace_and_channel(struct t_gui_buffer *buffer,
                                            struct t_slack_workspace **workspace,
                                            struct t_slack_channel **channel);

char *slack_buffer_typing_bar_cb(const void *pointer,
                                 void *data,
                                 struct t_gui_bar_item *item,
                                 struct t_gui_window *window,
                                 struct t_gui_buffer *buffer,
                                 struct t_hashtable *extra_info);

int slack_buffer_nickcmp_cb(const void *pointer, void *data,
                            struct t_gui_buffer *buffer,
                            const char *nick1,
                            const char *nick2);

int slack_buffer_close_cb(const void *pointer, void *data,
                          struct t_gui_buffer *buffer);

#endif /*SLACK_BUFFER_H*/
