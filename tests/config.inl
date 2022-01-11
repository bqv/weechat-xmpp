#include <doctest/doctest.h>

#include "../config.hh"

TEST_CASE("create config")
{
    weechat::xmpp::config cfg;

    CHECK(cfg.name() == weechat::xmpp::config::default_name);
}
