// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "weechat-plugin.h"
#include "slack.h"
#include "slack-workspace.h"
#include "slack-channel.h"
#include "slack-buffer.h"
#include "slack-emoji.h"

#include "slack-emoji.inc"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

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

static size_t modified_wagner_fischer(const char *src, const char *targ)
{
    size_t len = strlen(targ) + 1;
    size_t above[len], below[len];
    for (size_t *k = above, c = 0; k < above + len; ++k, ++c) *k = c;

    const char *src_at = src, *targ_at;
    for (size_t j = 1; j < strlen(src) + 1; ++j)
    {
        *below = j;
        targ_at = targ;
        for (size_t *d = above, *a = above + 1, *l = below, *c = below + 1;
             c < below + len; ++d, ++a, ++l, ++c)
        {
            /*        |-------------replace-----------|       |isrt|  |delt|   */
            *c = MIN( *src_at == *targ_at ? *d : *d + 1, MIN( *a + 0, *l + 1 ) );
            ++targ_at;
        }
        for (size_t *a = above, *b = below; a < above + len; ++a, ++b) *a = *b;
        ++src_at;
    }

    return above[len-1];
}

static size_t longest_common_substring(const char *X, const char *Y)
{
    const size_t n = strlen(X);
    const size_t m = strlen(Y);
    size_t i, j, result = 0;
    size_t **L;

    L = malloc(sizeof(size_t *) * (n + 1));
    L[0] = malloc(sizeof(size_t) * (m + 1) * (n + 1));
    
    for (i = 0; i <= n; i++)
        L[i] = (*L + (m + 1) * i);
  
    /* Following steps build L[n+1][m+1] in bottom up fashion. Note 
       that L[i][j] contains length of LCS of X[0..i-1] and Y[0..j-1] */
    for (i = 0; i <= n; i++)
    {
        for (j = 0; j <= m; j++)
        {
            if (i == 0 || j == 0)
            {
                L[i][j] = 0;
            }
            else if (X[i-1] == Y[j-1])
            {
                L[i][j] = L[i - 1][j - 1] + 1;
                if (result < L[i][j])
                    result = L[i][j];
            }
            else
            {
                L[i][j] = 0;
            }
        }
    }
    
    /* result now contains length of LCS for X[0..n-1] and Y[0..m-1] */
    free(L[0]);
    free(L);
    return result;
}

int slack_emoji_complete_by_name_cb(const void *pointer, void *data,
                                    const char *completion_item,
                                    struct t_gui_buffer *buffer,
                                    struct t_gui_completion *completion)
{
    struct t_slack_workspace_emoji *ptr_emoji;
    struct t_slack_workspace *workspace;
    struct t_slack_channel *channel;
    
    (void) pointer;
    (void) data;
    (void) completion_item;

    workspace = NULL;
    slack_buffer_get_workspace_and_channel(buffer, &workspace, &channel);

    size_t i, emoji_count = sizeof(slack_emoji_by_name)
        / sizeof(struct t_slack_emoji_by_name);

    if (workspace)
    {
        for (ptr_emoji = workspace->emoji; ptr_emoji;
             ptr_emoji = ptr_emoji->next_emoji)
            weechat_hook_completion_list_add(completion,
                                            ptr_emoji->name,
                                            0, WEECHAT_LIST_POS_END);
    
        for (i = 0; i < emoji_count; i++)
            weechat_hook_completion_list_add(completion,
                                            slack_emoji_by_name[i].name,
                                            0, WEECHAT_LIST_POS_END);
    }

    return WEECHAT_RC_OK;
}

int slack_emoji_input_complete_cb(const void *pointer, void *data,
                                  struct t_gui_buffer *buffer,
                                  const char *command)
{
    struct t_slack_emoji_by_name *closest_emoji;
    int input_pos, input_length, start, end;
    char *new_string, *word, *new_pos;
    const char *input_string;

    (void) pointer;
    (void) data;
    (void) command;

    input_string = weechat_buffer_get_string(buffer, "input");
    input_length = strlen(input_string);
    input_pos = weechat_buffer_get_integer(buffer, "input_pos");
    for (start = input_pos; start > 0 && input_string[start] != ':'; start--)
        if (input_string[start] == ' ') { break; }
    for (end = input_pos; end < input_length && input_string[end] != ' '; end++)
        if (input_string[end] == ':') { end++; break; }

    if (input_string[start] != ':')
        return WEECHAT_RC_OK;
    else
        word = strndup(&input_string[start], end - start);
    
    size_t emoji_count = sizeof(slack_emoji_by_name)
        / sizeof(struct t_slack_emoji_by_name);
    closest_emoji = malloc(sizeof(slack_emoji_by_name));
    memcpy(closest_emoji, slack_emoji_by_name,
           sizeof(slack_emoji_by_name));

    int edit_dist_cmp(const void *p1, const void *p2)
    {
        const struct t_slack_emoji_by_name *e1 = p1;
        const struct t_slack_emoji_by_name *e2 = p2;
        size_t d1 = modified_wagner_fischer(e1->name, word);
        size_t d2 = modified_wagner_fischer(e2->name, word);
        if (d1 == d2)
        {
            size_t l1 = longest_common_substring(e1->name, word);
            size_t l2 = longest_common_substring(e2->name, word);
            return (l1 < l2) - (l1 > l2);
        }
        return (d1 > d2) - (d1 < d2);
    };
    qsort(closest_emoji, emoji_count,
          sizeof(struct t_slack_emoji_by_name),
          edit_dist_cmp);

    size_t new_length = snprintf(NULL, 0, "%.*s%s%s",
                                 start, input_string,
                                 closest_emoji[0].name,
                                 &input_string[end]) + 1;
    new_string = malloc(new_length);
    snprintf(new_string, new_length, "%.*s%s%s",
             start, input_string,
             closest_emoji[0].name,
             &input_string[end]);
    weechat_buffer_set(buffer, "input", new_string);
    
    size_t new_pos_len = snprintf(NULL, 0, "%lu",
                                  (unsigned long)(start +
                                      strlen(closest_emoji[0].name) - 1));
    new_pos = malloc(new_pos_len);
    snprintf(new_pos, new_pos_len, "%lu",
             (unsigned long)(start +
                 strlen(closest_emoji[0].name) - 1));
    weechat_buffer_set(buffer, "input_pos", new_pos);
    
    free(new_pos);
    free(new_string);
    free(closest_emoji);
    free(word);
    return WEECHAT_RC_OK_EAT;
}

int slack_emoji_input_replace_cb(const void *pointer, void *data,
                                 struct t_gui_buffer *buffer,
                                 const char *command)
{
    (void) pointer;
    (void) data;
    (void) buffer;
    (void) command;

    /* TBI */
    
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
