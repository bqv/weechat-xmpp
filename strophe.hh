// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <fmt/core.h>
#include <memory>
#include <functional>
#include <type_traits>
#include <strophe.h>

namespace libstrophe {

    template<typename T, typename CFun, typename DFun,
        CFun &f_create, DFun &f_destroy, typename Base = T>
    class type {
    private:
        T *_ptr;

    protected:
        typedef T* pointer_type;

        inline type(T *ptr) : _ptr(ptr) {
        }

        template<typename Fun, Fun &func, int success = 0, typename... Args,
            typename = std::enable_if_t<std::is_same_v<int, std::invoke_result_t<Fun, pointer_type, std::decay_t<Args>...>>>>
        inline void call_checked(Args&&... args) {
            int ret = func(*this, std::forward<Args>(args)...);
            if (ret != success) throw std::runtime_error(
                fmt::format("Strophe Error: expected {}, was {}", success, ret));
        }

        template<typename Fun, Fun &func, int success = 0, typename... Args,
            typename = std::enable_if_t<std::is_same_v<void, std::invoke_result_t<Fun, pointer_type, std::decay_t<Args>...>>>>
        inline void call(Args&&... args) {
            func(*this, std::forward<Args>(args)...);
        }

        template<typename Fun, Fun &func, typename... Args,
            typename = std::enable_if_t<!std::is_same_v<void, std::invoke_result_t<Fun, pointer_type, std::decay_t<std::decay_t<Args>>...>>>>
        inline typename std::invoke_result_t<Fun, pointer_type, std::decay_t<std::decay_t<Args>>...>
        call(Args&&... args) {
            return func(*this, std::forward<Args>(args)...);
        }

    public:
        inline explicit type() : _ptr(nullptr) {
        }

        template<typename... Args>
        inline explicit type(Args&&... args) : type() {
            _ptr = f_create(std::forward<Args>(args)...);
        }

        inline ~type() {
            if (_ptr)
                f_destroy(reinterpret_cast<Base*>(_ptr));
            _ptr = nullptr;
        }

        type(const type &other) = delete; /* no copy construction */
        type(type &&other) = default;

        template<typename... Args>
        inline void create(Args&&... args) {
            if (_ptr)
                f_destroy(reinterpret_cast<Base*>(_ptr));
            _ptr = f_create(std::forward<Args>(args)...);
        }

        type& operator =(const type &other) = delete; /* no copy assignment */
        type& operator =(type &&other) = default;

        inline operator bool() const { return _ptr; }

        inline T* operator *() { return _ptr; }

        inline operator T*() { return _ptr; }

        inline operator const T*() const { return _ptr; }
    };

    inline auto initialize = xmpp_initialize;
    inline auto shutdown = xmpp_shutdown;

    typedef type<xmpp_ctx_t,
        decltype(xmpp_ctx_new), decltype(xmpp_ctx_free),
        xmpp_ctx_new, xmpp_ctx_free> context_type;
    class context : public context_type {
    public:
        using context_type::context_type;

        inline auto set_verbosity(auto &&...args) {
            return call<decltype(xmpp_ctx_set_verbosity),
                        xmpp_ctx_set_verbosity>(args...);
        }
    };

    typedef type<xmpp_conn_t,
        decltype(xmpp_conn_new), decltype(xmpp_conn_release),
        xmpp_conn_new, xmpp_conn_release> connection_type;
    class connection : public connection_type {
    public:
        using connection_type::connection_type;

        inline connection(context& ctx) {
            create(*ctx);
        }

        inline auto get_context(auto &&...args) {
            return call<decltype(xmpp_conn_get_context),
                        xmpp_conn_get_context>(args...);
        }

        inline auto get_flags(auto &&...args) {
            return call<decltype(xmpp_conn_get_flags),
                        xmpp_conn_get_flags>(args...);
        }

        inline auto set_keepalive(auto &&...args) {
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            return call<decltype(xmpp_conn_set_keepalive),
                        xmpp_conn_set_keepalive>(args...);
#pragma GCC diagnostic pop
        }

        inline auto set_jid(auto &&...args) {
            return call<decltype(xmpp_conn_set_jid),
                        xmpp_conn_set_jid>(args...);
        }

        inline auto set_pass(auto &&...args) {
            return call<decltype(xmpp_conn_set_pass),
                        xmpp_conn_set_pass>(args...);
        }

        inline auto set_flags(auto &&...args) {
            return call<decltype(xmpp_conn_set_flags),
                        xmpp_conn_set_flags>(args...);
        }

        inline auto send(auto &&...args) {
            return call<decltype(xmpp_send), xmpp_send>(args...);
        }

        inline auto connect_client(auto &&...args) {
            return call<decltype(xmpp_connect_client), xmpp_connect_client>(args...);
        }

        inline auto handler_add(auto &&...args) {
            return call<decltype(xmpp_handler_add), xmpp_handler_add>(args...);
        }
    };

    typedef type<xmpp_stanza_t,
        decltype(xmpp_stanza_new), decltype(xmpp_stanza_release),
        xmpp_stanza_new, xmpp_stanza_release> stanza_type;
    class stanza : public stanza_type {
    public:
        using stanza_type::stanza_type;

        inline static stanza reply(auto &&...args) {
            return stanza(xmpp_stanza_reply(args...));
        }

        inline stanza get_name(auto &&...args) {
            return call<decltype(xmpp_stanza_get_name),
                   xmpp_stanza_get_name>(args...);
        }

        inline stanza get_ns(auto &&...args) {
            return call<decltype(xmpp_stanza_get_ns),
                   xmpp_stanza_get_ns>(args...);
        }

        inline stanza add_child(auto &&...args) {
            call<decltype(xmpp_stanza_add_child),
                xmpp_stanza_add_child>(args...);
            return std::move(*this);
        }

        inline stanza set_name(auto &&...args) {
            call<decltype(xmpp_stanza_set_name),
                xmpp_stanza_set_name>(args...);
            return std::move(*this);
        }

        inline stanza set_ns(auto &&...args) {
            call<decltype(xmpp_stanza_set_ns),
                xmpp_stanza_set_ns>(args...);
            return std::move(*this);
        }

        inline stanza set_text(auto &&...args) {
            call<decltype(xmpp_stanza_set_text),
                xmpp_stanza_set_text>(args...);
            return std::move(*this);
        }

        inline stanza set_type(auto &&...args) {
            call<decltype(xmpp_stanza_set_type),
                xmpp_stanza_set_type>(args...);
            return std::move(*this);
        }
    };
}
