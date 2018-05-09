// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
