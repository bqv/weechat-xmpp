// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_PGP_H_
#define _WEECHAT_XMPP_PGP_H_

struct t_pgp
{
    struct rnp_ffi_st *context;
    const char *keyid;
};

void pgp__init(struct t_pgp **pgp, const char *pub, const char *sec);

void pgp__free(struct t_pgp *pgp);

char *pgp__decrypt(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *ciphertext);

char *pgp__encrypt(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *target, const char *message);

char *pgp__verify(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *certificate);

#endif /*WEECHAT_XMPP_PGP_H*/
