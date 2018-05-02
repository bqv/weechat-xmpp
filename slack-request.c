#include <libwebsockets.h>
#include <json.h>
#include <stdlib.h>
#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-request.h"

struct t_slack_request *slack_request_alloc(
                               struct t_slack_workspace *workspace)
{
    struct t_slack_request *request;

    request = malloc(sizeof(struct t_slack_request));
    memset(request, 0, sizeof(struct t_slack_request));

    request->workspace = workspace;
    request->idx = workspace->idx++;

    return request;
}
