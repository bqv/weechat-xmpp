// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <json.h>
#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "xmpp.h"
#include "xmpp-config.h"
#include "xmpp-connection.h"
//#include "api/xmpp-api-hello.h"
//#include "api/xmpp-api-error.h"
//#include "api/xmpp-api-message.h"
//#include "api/xmpp-api-user-typing.h"

xmpp_conn_t *xmpp_connection;

void xmpp_log_emit_weechat(void *const userdata, const xmpp_log_level_t level, const char *const area, const char *const msg)
{
    (void) userdata;

    time_t date = time(NULL);
    const char *timestamp = weechat_util_get_time_string(&date);

    weechat_printf(
        NULL,
        _("%s%s %d | %s: %s - %s"),
        weechat_prefix("error"), XMPP_PLUGIN_NAME,
        level, timestamp, area, msg);
}

xmpp_log_t xmpp_logger = {
    &xmpp_log_emit_weechat,
    NULL
};

void xmpp_connection_init()
{
    xmpp_initialize();
}

void xmpp_connection_autoconnect()
{
    xmpp_connection_connect(weechat_config_string(xmpp_config_serverdef_jid),
                            weechat_config_string(xmpp_config_serverdef_password));
    weechat_printf(NULL, _("xmpp: %s # %s"),
                   weechat_config_string(xmpp_config_serverdef_jid),
                   weechat_config_string(xmpp_config_serverdef_password));
}

void xmpp_connection_connect(const char* jid, const char* password)
{
    xmpp_ctx_t *xmpp_context = xmpp_ctx_new(NULL, &xmpp_logger);

    xmpp_conn_t *xmpp_connection = xmpp_conn_new(xmpp_context);

    xmpp_connection = xmpp_conn_new(xmpp_context);
    xmpp_conn_set_jid(xmpp_connection, jid);
    xmpp_conn_set_pass(xmpp_connection, password);
  //struct lws_context_creation_info ctxinfo;
  //struct lws_client_connect_info ccinfo;
  //const char *url_protocol, *url_path;
  //char path[512];

  //memset(&ctxinfo, 0, sizeof(ctxinfo));
  //memset(&ccinfo, 0, sizeof(ccinfo));

  //ccinfo.port = 443;

  //if (lws_parse_uri(workspace->ws_url,
  //                  &url_protocol, &ccinfo.address,
  //                  &ccinfo.port, &url_path))
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: error connecting to xmpp: bad websocket uri"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME);
  //    return;
  //}

  //path[0] = '/';
  //strncpy(path + 1, url_path, sizeof(path) - 2);
  //path[sizeof(path) - 1] = '\0';

  //ccinfo.path = path;

  //ctxinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  //ctxinfo.port = CONTEXT_PORT_NO_LISTEN;
  //ctxinfo.protocols = protocols;
  //ctxinfo.uid = -1;
  //ctxinfo.gid = -1;

  //workspace->context = lws_create_context(&ctxinfo);
  //if (!workspace->context)
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: error connecting to xmpp: lws init failed"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME);
  //    return;
  //}
  //else
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: connecting to %s://%s:%d%s"),
  //        weechat_prefix("network"), XMPP_PLUGIN_NAME,
  //        url_protocol, ccinfo.address, ccinfo.port, path);
  //}

  //ccinfo.context = workspace->context;
  //ccinfo.ssl_connection = LCCSCF_USE_SSL;
  //ccinfo.host = ccinfo.address;
  //ccinfo.origin = ccinfo.address;
  //ccinfo.ietf_version_or_minus_one = -1;
  //ccinfo.protocol = protocols[0].name;
  //ccinfo.pwsi = &workspace->client_wsi;
  //ccinfo.userdata = workspace;

  //lws_client_connect_via_info(&ccinfo);
    return xmpp_connection;
}

int xmpp_connection_route_message(xmpp_conn_t *workspace,
                                  const char *type, json_object *message)
{
  //struct stringcase key;
  //key.string = type;

  //size_t case_count = sizeof(cases) / sizeof(cases[0]);
  //void *entry_ptr = bsearch(&key, cases, case_count,
  //        sizeof(struct stringcase), stringcase_cmp);

  //if (entry_ptr)
  //{
  //    struct stringcase *entry = (struct stringcase *)entry_ptr;
  //    return (*entry->func)(workspace, message);
  //}
  //else
  //{
  //    weechat_printf(
  //        workspace->buffer,
  //        _("%s%s: got unhandled message of type: %s"),
  //        weechat_prefix("error"), XMPP_PLUGIN_NAME,
  //        type);
        return 1;
  //}
}
