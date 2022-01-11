// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

int input__data_cb(const void *pointer, void *data,
                   struct t_gui_buffer *buffer,
                   const char *input_data);

int input__text_changed_cb(const void *pointer, void *data,
                           const char *signal, const char *type_data,
                           void *signal_data);
