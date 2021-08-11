#include <doctest/doctest.h>

#include "../weechat.hh"

TEST_CASE("create error")
{
    weechat::error err("content");

    CHECK(err.what() == "content");
}
