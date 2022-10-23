// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <string>
#include <optional>

namespace weechat
{
    class account;
    class channel;

    class user
    {
    private:
        struct profile
        {
            char *avatar_hash = nullptr;
            char *status_text = nullptr;
            char *status = nullptr;
            std::optional<std::string> idle;
            char *display_name = nullptr;
            char *email = nullptr;
            char *role = nullptr;
            char *affiliation = nullptr;
            char *pgp_id = nullptr;
            int omemo = 0;
        };

    private:
        char *name = nullptr;

        bool updated = false;

    public:
        char *id = nullptr;
        bool is_away = false;
        struct profile profile;

    public:
        user(weechat::account *account, weechat::channel *channel, const char *id, const char *display_name);

        static std::string get_colour(const char *name);
        static std::string get_colour_for_nicklist(const char *name);
        std::string get_colour();
        std::string get_colour_for_nicklist();
        static std::string as_prefix_raw(const char *name);
        static std::string as_prefix(const char *name);
        std::string as_prefix_raw();
        std::string as_prefix();

        static std::string as_prefix_raw(weechat::account *account, const char *id) {
            auto found = search(account, id);
            return found ? found->as_prefix_raw() : "";
        }
        static std::string as_prefix(weechat::account *account, const char *id) {
            auto found = search(account, id);
            return found ? found->as_prefix() : "";
        }

        static weechat::user *bot_search(weechat::account *account, const char *pgp_id);
        static weechat::user *search(weechat::account *account, const char *id);

        void nicklist_add(weechat::account *account, weechat::channel *channel);
        void nicklist_remove(weechat::account *account, weechat::channel *channel);
    };
}
