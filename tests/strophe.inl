#include <doctest/doctest.h>

#include "../strophe.hh"

TEST_CASE("create context")
{
    xmpp::context ctx(0);

    CHECK(ctx.get());
}
