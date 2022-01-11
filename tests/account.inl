#include <doctest/doctest.h>

#include "../account.hh"

TEST_CASE("create account")
{
    weechat::xmpp::account acc("demo");

    CHECK(acc.name == "demo");
}
