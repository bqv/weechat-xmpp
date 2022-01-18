// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <functional>
#include <stdexcept>
#include <gcrypt.h>

namespace gcrypt {

    class version_error : public std::runtime_error {
    private:
        const char *const message = "GCrypt: library version mismatch";
    public:
        version_error() noexcept : runtime_error(GCRYPT_VERSION) {
        }

        virtual const char* what() const noexcept {
            return message;
        }
    };

    void check_version() {
        if (!gcry_check_version(GCRYPT_VERSION))
            throw gcrypt::version_error();
    }

}
