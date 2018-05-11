// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef _SLACK_EMOJI_H_
#define _SLACK_EMOJI_H_

const char *slack_emoji_get_unicode_by_name(const char *name);

const char *slack_emoji_get_unicode_by_text(const char *text);

const char *slack_emoji_get_text_by_name(const char *name);
    
const char *slack_emoji_get_text_by_text(const char *text);

#endif /*SLACK_EMOJI_H*/
