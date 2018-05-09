// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_INPUT_H_
#define _SLACK_INPUT_H_

int slack_input_data_cb(const void *pointer, void *data,
                        struct t_gui_buffer *buffer,
                        const char *input_data);

#endif /*SLACK_INPUT_H*/
