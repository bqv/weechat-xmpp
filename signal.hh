// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <fmt/core.h>
#include <memory>
#include <functional>
#include <type_traits>
#include <signal_protocol.h>
#include <key_helper.h>
#include <session_builder.h>
#include <session_cipher.h>
#include <session_pre_key.h>
#include <protocol.h>
#include <curve.h>

namespace libsignal {

    template<typename T>
    struct deleter {
        void operator() (T *ptr) { SIGNAL_UNREF(ptr); }
    };

    template<typename T>
    using object = std::unique_ptr<T, deleter<T>>;

    template<typename T, typename CFun, typename DFun,
        CFun &f_create, DFun &f_destroy, typename Base = T>
    class type {
    private:
        T *_ptr;

    public:
        typedef T* pointer_type;

        inline explicit type() : _ptr(nullptr) {
        }

        template<typename... Args>
        inline explicit type(Args&&... args) : type() {
            f_create(&_ptr, std::forward<Args>(args)...);
        }

        inline ~type() {
            if (_ptr)
                f_destroy(reinterpret_cast<Base*>(_ptr));
            _ptr = nullptr;
        }

        template<typename... Args>
        inline void create(Args&&... args) {
            if (_ptr)
                f_destroy(reinterpret_cast<Base*>(_ptr));
            _ptr = nullptr;
            f_create(&_ptr, std::forward<Args>(args)...);
        }

        inline operator bool() const { return _ptr; }

        inline operator T*() { return _ptr; }

        inline operator const T*() const { return _ptr; }

    protected:
        inline type(T *ptr) {
            _ptr = ptr;
        }

        template<typename Fun, Fun &func, int success = 0, typename... Args,
            typename = std::enable_if_t<std::is_same_v<int, std::invoke_result_t<Fun, pointer_type, Args...>>>>
        inline void call(Args&&... args) {
            int ret = func(*this, std::forward<Args>(args)...);
            if (ret != success) throw std::runtime_error(
                fmt::format("Signal Error: expected {}, was {}", success, ret));
        }

        template<typename Fun, Fun &func, typename... Args,
            typename = std::enable_if_t<!std::is_same_v<int, std::invoke_result_t<Fun, pointer_type, Args...>>>>
        inline std::invoke_result<Fun, pointer_type, Args...>::type
        call(Args&&... args) {
            return func(*this, std::forward<Args>(args)...);
        }
    };

    typedef type<struct signal_context,
        decltype(signal_context_create), decltype(signal_context_destroy),
        signal_context_create, signal_context_destroy> context_type;
    class context : public context_type {
    public:
        using context_type::context_type;

        context& operator =(const context &other) = delete;
        context& operator =(context &&other) = default;

        inline auto set_log_function(auto &&...args) {
            return call<decltype(signal_context_set_log_function),
                        signal_context_set_log_function>(args...);
        }

        inline auto set_crypto_provider(auto &&...args) {
            return call<decltype(signal_context_set_crypto_provider),
                        signal_context_set_crypto_provider>(args...);
        }

        inline auto set_locking_functions(auto &&...args) {
            return call<decltype(signal_context_set_locking_functions),
                        signal_context_set_locking_functions>(args...);
        }
    };

    typedef type<struct signal_protocol_store_context,
        decltype(signal_protocol_store_context_create),
        decltype(signal_protocol_store_context_destroy),
        signal_protocol_store_context_create,
        signal_protocol_store_context_destroy> store_context_type;
    class store_context : public store_context_type {
    public:
        using store_context_type::store_context_type;

        inline auto set_identity_key_store(auto &&...args) {
            return call<decltype(signal_protocol_store_context_set_identity_key_store),
                        signal_protocol_store_context_set_identity_key_store>(args...);
        }

        inline auto set_pre_key_store(auto &&...args) {
            return call<decltype(signal_protocol_store_context_set_pre_key_store),
                        signal_protocol_store_context_set_pre_key_store>(args...);
        }

        inline auto set_signed_pre_key_store(auto &&...args) {
            return call<decltype(signal_protocol_store_context_set_signed_pre_key_store),
                        signal_protocol_store_context_set_signed_pre_key_store>(args...);
        }

        inline auto set_session_store(auto &&...args) {
            return call<decltype(signal_protocol_store_context_set_session_store),
                        signal_protocol_store_context_set_session_store>(args...);
        }

        inline auto set_sender_key_store(auto &&...args) {
            return call<decltype(signal_protocol_store_context_set_sender_key_store),
                        signal_protocol_store_context_set_sender_key_store>(args...);
        }
    };

    typedef type<struct ec_public_key,
        decltype(curve_decode_point),
        decltype(ec_public_key_destroy),
        curve_decode_point,
        ec_public_key_destroy,
        signal_type_base> public_key_type;
    class public_key : public public_key_type {
    public:
        using public_key_type::public_key_type;

        inline static public_key deserialize(auto &&...args) {
            pointer_type pointer;
            ec_public_key_deserialize(&pointer, args...);
            return public_key(pointer);
        }

        inline auto serialize(auto &&...args) {
            return call<decltype(ec_public_key_serialize),
                        ec_public_key_serialize>(args...);
        }

        friend class identity_key_pair;
    };

    typedef type<struct ec_private_key,
        decltype(curve_decode_private_point),
        decltype(ec_private_key_destroy),
        curve_decode_private_point,
        ec_private_key_destroy,
        signal_type_base> private_key_type;
    class private_key : public private_key_type {
    public:
        using private_key_type::private_key_type;

        inline static private_key deserialize(auto &&...args) {
            pointer_type pointer;
            ec_private_key_deserialize(&pointer, args...);
            return private_key(pointer);
        }

        inline auto serialize(auto &&...args) {
            return call<decltype(ec_private_key_serialize),
                        ec_private_key_serialize>(args...);
        }

        friend class identity_key_pair;
    };

    typedef type<struct ratchet_identity_key_pair,
        decltype(ratchet_identity_key_pair_create),
        decltype(ratchet_identity_key_pair_destroy),
        ratchet_identity_key_pair_create,
        ratchet_identity_key_pair_destroy,
        signal_type_base> identity_key_pair_type;
    class identity_key_pair : public identity_key_pair_type {
    public:
        using identity_key_pair_type::identity_key_pair_type;

        inline static identity_key_pair generate(auto &&...args) {
            pointer_type pointer;
            signal_protocol_key_helper_generate_identity_key_pair(&pointer, args...);
            return identity_key_pair(pointer);
        }

        inline public_key get_public(auto &&...args) {
            return call<decltype(ratchet_identity_key_pair_get_public),
                        ratchet_identity_key_pair_get_public>(args...);
        }

        inline private_key get_private(auto &&...args) {
            return call<decltype(ratchet_identity_key_pair_get_private),
                        ratchet_identity_key_pair_get_private>(args...);
        }
    };

}
