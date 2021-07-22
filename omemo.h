// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _WEECHAT_XMPP_OMEMO_H_
#define _WEECHAT_XMPP_OMEMO_H_

extern const char *OMEMO_ADVICE;

struct t_identity
{
    uint8_t *key;
    size_t length;
};

struct t_omemo
{
  //omemo_crypto_provider provider;
  //axc_context *context;
  //axc_bundle *a_bundle;
  //omemo_bundle *o_bundle;

    struct t_identity *identity;

    uint32_t device_id;
};

void omemo__init(struct t_omemo **omemo, uint32_t device,
                 struct t_identity *identity);

void omemo__free(struct t_omemo *omemo);

#endif /*WEECHAT_XMPP_OMEMO_H*/
