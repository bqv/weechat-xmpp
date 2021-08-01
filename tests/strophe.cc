#include <iostream>
#include <doctest/doctest.h>

#include "../strophe.hh"

TEST_CASE("create context")
{
    xmpp::context ctx;

    CHECK(ctx.get());
}
