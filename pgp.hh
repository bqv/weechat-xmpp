// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <string>
#include <vector>

namespace weechat::xmpp
{
    extern const char *PGP_ADVICE;

    class pgp
    {
    public:
        struct gpgme_context *gpgme;
        const char *keyid;

    public:
        pgp();

        ~pgp();

        char *decrypt(struct t_gui_buffer *buffer, const char *ciphertext);

        char *encrypt(struct t_gui_buffer *buffer, const char *source, std::vector<std::string>&& target, const char *message);

        char *verify(struct t_gui_buffer *buffer, const char *certificate);

        char *sign(struct t_gui_buffer *buffer, const char *source, const char *message);
    };
}
