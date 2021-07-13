// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "util.h"

int char_cmp(const void *p1, const void *p2)
{
    return *(const char *)p1 == *(const char *)p2;
}
