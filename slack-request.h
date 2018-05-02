#ifndef _SLACK_REQUEST_H_
#define _SLACK_REQUEST_H_

struct t_slack_request
{
    struct t_slack_workspace *workspace;

    char *uri;
    struct lws *client_wsi;
    struct lws_context *context;
    struct t_json_chunk *json_chunks;

    struct t_slack_request *next;
};

struct t_slack_request *slack_request_alloc(
                               struct t_slack_workspace *workspace);

#endif /*SLACK_REQUEST_H*/
