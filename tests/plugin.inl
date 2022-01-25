#include <doctest/doctest.h>

#include <weechat/weechat-plugin.h>
#include "../plugin.hh"

TEST_CASE("weechat")
{
    std::string current("20211106-01");
    
    SUBCASE("plugin api match")
    {
        CHECK(current == WEECHAT_PLUGIN_API_VERSION);
    }
}
