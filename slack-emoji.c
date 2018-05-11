// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-emoji.h"

#include "slack-emoji.inc"

static int emoji_byname_cmp(const void *p1, const void *p2)
{
    return strcasecmp(((struct t_slack_emoji_by_name *)p1)->name,
                      ((struct t_slack_emoji_by_name *)p2)->name);
}

static int emoji_bytext_cmp(const void *p1, const void *p2)
{
    return strcasecmp(((struct t_slack_emoji_by_text *)p1)->text,
                      ((struct t_slack_emoji_by_text *)p2)->text);
}

const char *slack_emoji_get_unicode_by_name(const char *name)
{
    struct t_slack_emoji_by_name *result;
    struct t_slack_emoji_by_name key;
    key.name = name;

    size_t emoji_count = sizeof(slack_emoji_by_name)
        / sizeof(struct t_slack_emoji_by_name);
    result = (struct t_slack_emoji_by_name *)bsearch(
        &key, slack_emoji_by_name, emoji_count,
        sizeof(struct t_slack_emoji_by_name),
        emoji_byname_cmp);
    
    return result->unicode;
}

const char *slack_emoji_get_unicode_by_text(const char *text)
{
    struct t_slack_emoji_by_text *result;
    struct t_slack_emoji_by_text key;
    key.text = text;

    size_t emoji_count = sizeof(slack_emoji_by_text)
        / sizeof(struct t_slack_emoji_by_text);
    result = (struct t_slack_emoji_by_text *)bsearch(
        &key, slack_emoji_by_text, emoji_count,
        sizeof(struct t_slack_emoji_by_text),
        emoji_bytext_cmp);
    
    return result->unicode;
}

const char *slack_emoji_get_text_by_name(const char *name)
{
    struct t_slack_emoji_by_name *result;
    struct t_slack_emoji_by_name key;
    key.name = name;

    size_t emoji_count = sizeof(slack_emoji_by_name)
        / sizeof(struct t_slack_emoji_by_name);
    result = (struct t_slack_emoji_by_name *)bsearch(
        &key, slack_emoji_by_name, emoji_count,
        sizeof(struct t_slack_emoji_by_name),
        emoji_byname_cmp);
    
    return result->text_to;
}

const char *slack_emoji_get_text_by_text(const char *text)
{
    struct t_slack_emoji_by_text *result;
    struct t_slack_emoji_by_text key;
    key.text = text;

    size_t emoji_count = sizeof(slack_emoji_by_text)
        / sizeof(struct t_slack_emoji_by_text);
    result = (struct t_slack_emoji_by_text *)bsearch(
        &key, slack_emoji_by_text, emoji_count,
        sizeof(struct t_slack_emoji_by_text),
        emoji_bytext_cmp);
    
    return result->text_to;
}
