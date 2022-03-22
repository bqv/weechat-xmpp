// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <regex>
#include <string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "util.hh"

int char_cmp(const void *p1, const void *p2)
{
    return *(const char *)p1 == *(const char *)p2;
}

char *exec(const char *command)
{
    // use hook_process instead!
    char buffer[128];
    char **result = weechat_string_dyn_alloc(256);

    // Open pipe to file
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        return (char*)strdup("popen failed!");
    }

    // read till end of process:
    while (!feof(pipe)) {

        // use buffer to read and add to result
        if (fgets(buffer, 128, pipe) != NULL)
            weechat_string_dyn_concat(result, buffer, -1);
    }

    pclose(pipe);
    weechat_string_dyn_free(result, 0);
    return *result;
}

char *stanza_xml(xmpp_stanza_t *stanza)
{
    char *result;
    size_t len;
    xmpp_stanza_to_text(stanza, &result, &len);
    return result;
}

std::string unescape(const std::string& str)
{
    std::regex regex("\\&\\#(\\d+);");
    std::sregex_iterator begin(str.begin(), str.end(), regex), end;
    if (begin != end)
    {
        std::ostringstream output;
        do {
            std::smatch const& m = *begin;
            if (m[1].matched)
            {
                auto ch = static_cast<char>(std::stoul(m.str(1)));
                output << m.prefix() << ch;
            }
            else output << m.prefix() << m.str(0);
        } while (++begin != end);
        output << str.substr(str.size() - begin->position());
        return output.str();
    }
    return str;
}
