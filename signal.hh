// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <functional>
#include <signal_protocol.h>

namespace libsignal {

    template<typename T>
    struct deleter {
        void operator() (T *ptr) { SIGNAL_UNREF(ptr); }
    };

    template<>
    struct deleter<struct signal_context> {
        void operator() (struct signal_context *ptr)
        { signal_context_destroy(ptr); }
    };

    template<>
    struct deleter<struct signal_protocol_store_context> {
        void operator() (struct signal_protocol_store_context *ptr)
        { signal_protocol_store_context_destroy(ptr); }
    };

    template<>
    struct deleter<struct ratchet_identity_key_pair> {
        void operator() (struct ratchet_identity_key_pair *ptr)
        { ratchet_identity_key_pair_destroy(
                reinterpret_cast<signal_type_base*>(ptr)); }
    };

    template<typename T>
    using object = std::unique_ptr<T, deleter<T>>;

    template<typename T, typename... Args>
    object<T> make(int (*fun)(T**,Args...), Args... args) {
        T *result;
        fun(&result, args...);
        return object<T>(result);
    };

    typedef object<struct signal_context> context;

    typedef object<struct signal_protocol_store_context> store_context;

    typedef object<struct ratchet_identity_key_pair> identity_key_pair;

    typedef object<struct ec_public_key> public_key;

    typedef object<struct ec_private_key> private_key;

}
