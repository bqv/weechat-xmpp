// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

void buffer__get_account_and_channel(struct t_gui_buffer *buffer,
                                     struct t_account **account,
                                     struct t_channel **channel);

char *buffer__typing_bar_cb(const void *pointer, void *data,
                            struct t_gui_bar_item *item,
                            struct t_gui_window *window,
                            struct t_gui_buffer *buffer,
                            struct t_hashtable *extra_info);

int buffer__nickcmp_cb(const void *pointer, void *data,
                       struct t_gui_buffer *buffer,
                       const char *nick1,
                       const char *nick2);

int buffer__close_cb(const void *pointer, void *data,
                     struct t_gui_buffer *buffer);
