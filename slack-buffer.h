#ifndef _SLACK_BUFFER_H_
#define _SLACK_BUFFER_H_

int slack_buffer_nickcmp_cb(const void *pointer, void *data,
                            struct t_gui_buffer *buffer,
                            const char *nick1,
                            const char *nick2);

int slack_buffer_close_cb(const void *pointer, void *data,
                          struct t_gui_buffer *buffer);

#endif /*SLACK_BUFFER_H*/
