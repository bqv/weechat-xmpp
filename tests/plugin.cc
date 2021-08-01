#include <iostream>
#include <doctest/doctest.h>

#include "../plugin.hh"

TEST_CASE("placeholder")
{
    int argc = 2;
    const char *argv[2] = {"a", "b"};
    
    SUBCASE("takes no arguments")
    {
        CHECK(argc != 1);
    }

  //weechat::plugin c;
  //CHECK(&c.name() == NULL);
}
