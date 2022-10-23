// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <weechat/weechat-plugin.h>
#include <strophe.h>

#include "../plugin.hh"
#include "../account.hh"
#include "account.hh"

bool weechat::config_account::write()
{
    if (!option_jid.write()) return false;
    if (!option_password.write()) return false;
    if (!option_tls.write()) return false;
    if (!option_nickname.write()) return false;
    if (!option_autoconnect.write()) return false;
    if (!option_resource.write()) return false;
    if (!option_status.write()) return false;
    if (!option_pgp_path.write()) return false;
    if (!option_pgp_keyid.write()) return false;
    return true;
}
