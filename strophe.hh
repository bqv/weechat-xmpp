// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <any>

namespace xmpp {
    extern "C" {
#include <strophe.h>
    }

    template<typename UserData>
    class logger : public xmpp_log_t {
    private:
        UserData& m_data;
    public:
        explicit logger<UserData>(UserData& data);

        class level {
        public:
            level() = default;
            constexpr level(const xmpp_log_level_t lvl) : value(lvl) { }

            inline operator xmpp_log_level_t () const { return this->value; }
            explicit operator bool () = delete;
            constexpr bool operator== (level lvl) const { return this->value == lvl.value; }
            constexpr bool operator!= (level lvl) const { return this->value != lvl.value; }
            constexpr bool operator<= (level lvl) const { return this->value <= lvl.value; }
            constexpr bool operator>= (level lvl) const { return this->value >= lvl.value; }
            constexpr bool operator<  (level lvl) const { return this->value <  lvl.value; }
            constexpr bool operator>  (level lvl) const { return this->value >  lvl.value; }

            inline const char *name() const {
                static const char *names[] = {"debug", "info", "warn", "error", nullptr};

                return names[this->value];
            }
        private:
            xmpp_log_level_t value;
        };

        inline static level debug = level(XMPP_LEVEL_DEBUG);
        inline static level info = level(XMPP_LEVEL_INFO);
        inline static level warn = level(XMPP_LEVEL_WARN);
        inline static level error = level(XMPP_LEVEL_ERROR);

        static void emit_weechat(UserData& data, const level level,
                                 std::string_view area, std::string_view msg);
    };

    typedef std::unique_ptr<xmpp_ctx_t,
                            std::function<void(xmpp_ctx_t*)>> xmpp_ctx_ptr;

    class context : public xmpp_ctx_ptr {
    public:
        template<typename UserData = void*>
        explicit context(UserData& logger_data);
        explicit context(xmpp_ctx_ptr ptr);
        explicit context(xmpp_ctx_t *ptr);
        ~context();

        inline operator xmpp_ctx_t* () { return this->get(); }

    private:
        std::any m_logger;
    };

    typedef std::unique_ptr<xmpp_conn_t,
                            std::function<void(xmpp_conn_t*)>> xmpp_conn_ptr;

    class connection : public xmpp_conn_ptr {
    public:
        explicit connection(const context& context);
        explicit connection(xmpp_conn_ptr ptr);
        explicit connection(xmpp_conn_t *ptr);
        ~connection();

        inline operator xmpp_conn_t* () { return this->get(); }
    };

    void shutdown();
}

namespace xml {
    extern "C" {
#include <libxml/xmlwriter.h>
    }

    class error : virtual public std::runtime_error {
    public:
        explicit inline error(const std::string_view subject)
            : std::runtime_error(std::string(subject)) {
        }
        virtual ~error() throw () {}
    };


    template<typename T>
    void set_error_context(T *context);

    class document {
    protected:
        class node {
        public:
            explicit node(xmlNodePtr ptr);
            std::string name() const;

        private:
            const xmlNodePtr m_ptr;
        };

    public:
        explicit document(std::string_view text);
        ~document();

        std::optional<const node> root();
        std::string format() const;

        operator bool () const;

    private:
        const xmlDocPtr m_ptr;
        const std::size_t m_size;
    };
}
