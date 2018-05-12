// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-emoji.h"

#include "slack-emoji.inc"

#define MIN(a,b) (((a)<(b))?(a):(b))

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

static size_t levenshtein_dist(const char *s, size_t len_s, const char *t, size_t len_t)
{ 
    size_t cost;

    /* base case: empty strings */
    if (len_s == 0) return len_t;
    if (len_t == 0) return len_s;

    /* test if last characters of the strings match */
    if (s[len_s-1] == t[len_t-1])
        cost = 0;
    else
        cost = 1;

    /* delete char from s, delete char from t, and delete char from both */
    size_t delete  = levenshtein_dist(s, len_s - 1, t, len_t    ) + 1;
    size_t insert  = levenshtein_dist(s, len_s    , t, len_t - 1) + 1;
    size_t replace = levenshtein_dist(s, len_s - 1, t, len_t - 1) + cost;
    return MIN( MIN( delete, insert ), replace );
}

static size_t wagner_fischer(const char *src, const char *targ)
{
	size_t len = strlen(targ) + 1;
	size_t above[len], below[len];
	for (size_t *k = above, c = 0; k < above+len; ++k, ++c) *k=c;

	const char *src_at = src, *targ_at;
	for (size_t j = 1; j < strlen(src)+1; ++j)
	{
		*below = j;
		targ_at = targ;
		for (size_t *d = above, *a = above+1, *l = below, *c = below + 1;
             c < below + len; ++d, ++a, ++l, ++c)
		{
			*c = MIN( *src_at == *targ_at ? *d : *d + 1, MIN( *a + 1, *l + 1 ) );
			++targ_at;
		}
		for (size_t *a = above, *b = below; a < above + len; ++a, ++b) *a = *b;
		++src_at;
	}

	return above[len-1];
}

int slack_emoji_complete_by_name_cb(const void *pointer, void *data,
                                    const char *completion_item,
                                    struct t_gui_buffer *buffer,
                                    struct t_gui_completion *completion)
{
    struct t_slack_emoji_by_name *closest_emoji;

    (void) pointer;
    (void) data;

    weechat_printf(NULL, "Completing!");
    
    size_t i, emoji_count = sizeof(slack_emoji_by_name)
        / sizeof(struct t_slack_emoji_by_name);
    closest_emoji = malloc(sizeof(slack_emoji_by_name));
    memcpy(closest_emoji, slack_emoji_by_name,
           sizeof(slack_emoji_by_name));

    int edit_dist_cmp(const void *p1, const void *p2)
    {
        return 0;
    };
    qsort(closest_emoji, emoji_count,
          sizeof(struct t_slack_emoji_by_name),
          edit_dist_cmp);

    for (i = 0; i < emoji_count; i++)
    {
        weechat_printf(NULL, closest_emoji[i].name);
        weechat_hook_completion_list_add(completion, closest_emoji[i].name,
                                         0, WEECHAT_LIST_POS_END);
    }

    free(closest_emoji);
    return WEECHAT_RC_OK;
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

const char *slack_emoji_get_name_by_text(const char *text)
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
    
    return result->name_to;
}
