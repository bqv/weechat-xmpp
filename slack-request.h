// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_REQUEST_H_
#define _SLACK_REQUEST_H_

struct t_slack_request
{
    struct t_slack_workspace *workspace;

    int idx;

    const void *pointer;
    void *data;

    char *uri;
    struct lws *client_wsi;
    struct lws_context *context;
    struct t_json_chunk *json_chunks;

    struct t_slack_request *prev_request;
    struct t_slack_request *next_request;
};

struct t_slack_request *slack_request_alloc(
                               struct t_slack_workspace *workspace);

#endif /*SLACK_REQUEST_H*/
