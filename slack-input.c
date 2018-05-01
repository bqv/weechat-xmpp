#include "weechat-plugin.h"
#include "slack-input.h"

int slack_input_data(struct t_gui_buffer *buffer, const char *input_data)
{
    (void) buffer;
    (void) input_data;

    return WEECHAT_RC_OK;
}

int slack_input_data_cb(const void *pointer, void *data,
                        struct t_gui_buffer *buffer,
                        const char *input_data)
{
    (void) pointer;
    (void) data;

    return slack_input_data(buffer, input_data);
}
