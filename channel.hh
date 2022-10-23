// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <ctime>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <optional>

#define CHANNEL_MEMBERS_SPEAKING_LIMIT 128

namespace weechat
{
    class account;
    class user;

    class channel
    {
    public:
        enum class chat_type { MUC, PM };

        enum class transport { PLAIN, OMEMO, PGP, OTR, OX };

        static const char *transport_name(enum transport transport)
        {
            switch (transport)
            {
                case transport::PLAIN:
                    return "PLAINTEXT";
                case transport::OMEMO:
                    return "OMEMO";
                case transport::PGP:
                    return "PGP";
                case transport::OTR:
                    return "OTR";
                default:
                    return NULL;
            }
        }

        struct typing
        {
            union {
                char *id;
                weechat::user *user;
            };
            char *name;
            time_t ts;
        };

        struct member
        {
            char *id;

            char *role;
            char *affiliation;
        };

        struct topic
        {
            char *value = nullptr;
            char *creator = nullptr;
            time_t last_set = 0;
        };

        struct unread
        {
            char *id;
            char *thread;
        };

    private:
        topic topic;

        /* mpim */
        char *creator = nullptr;
        double last_read = 0.0;
        int unread_count = 0;
        int unread_count_display = 0;

        struct t_hook *typing_hook_timer = nullptr;
        struct t_hook *self_typing_hook_timer = nullptr;

    public:
        std::vector<weechat::channel::unread> unreads;

    public:
        std::string id;
        std::string name;
        enum chat_type type;
        enum transport transport = weechat::channel::transport::PLAIN;
        struct {
            int enabled;
            struct t_hashtable *devicelist_requests;
            struct t_hashtable *bundle_requests;
        } omemo;
        struct {
            int enabled = 1;
            std::unordered_set<std::string> ids;
        } pgp;
        struct {
            int enabled = 0;
       } otr;
        struct t_weelist *members_speaking[2] = { nullptr };
        std::vector<typing> self_typings;
        std::vector<typing> typings;
        std::unordered_map<std::string, member> members;

    public:
        struct t_gui_buffer *buffer;

    public:
        channel(weechat::account& account, enum chat_type type, const char *id, const char *name);
        ~channel();

        void set_transport(enum weechat::channel::transport transport, int force);

        struct t_gui_buffer *search_buffer(weechat::channel::chat_type type,
                                           const char *name);
        struct t_gui_buffer *create_buffer(weechat::channel::chat_type type,
                                           const char *name);

        void add_nicklist_groups();

        void member_speaking_add_to_list(const char *nick, int highlight);
        void member_speaking_add(const char *nick, int highlight);
        void member_speaking_rename(const char *old_nick, const char *new_nick);
        void member_speaking_rename_if_present(const char *nick);

        static int typing_cb(const void *pointer, void *data, int remaining_calls);
        typing *typing_search(const char *id);
        int add_typing(weechat::user *user);

        static int self_typing_cb(const void *pointer, void *data, int remaining_calls);
        typing *self_typing_search(weechat::user *user);
        int add_self_typing(weechat::user *user);

        static int hotlist_update_cb(const void *pointer, void *data,
                                     const char *signal, const char *type_data,
                                     void *signal_data);

        void free(channel *channel);
        void free_all();

        void update_topic(const char* title, const char* creator, int last_set);
        void update_name(const char* name);
        void update_purpose(const char* purpose, const char* creator, int last_set);

        member *add_member(const char *id, const char *client);
        member *member_search(const char *id);
        member *remove_member(const char *id, const char *reason);

        int send_message(std::string to, std::string body,
                         std::optional<std::string> oob = {});
        int send_message(const char *to, const char *body);

        void send_reads();
        void send_typing(weechat::user *user);
        void send_paused(weechat::user *user);

        void fetch_mam(const char *id, time_t *start, time_t *end, const char *after);

        weechat::account& account;
    };
}
