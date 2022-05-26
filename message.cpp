// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <strophe.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "account.hh"
#include "channel.hh"
#include "user.hh"
#include "message.hh"

static const char format_regex[] = "<([^>]*?)>";
static const size_t max_groups = 2;

char *message__translate_code(weechat::account *account,
                                   const char *code)
{
    decltype(account->channels)::iterator channel;
    weechat::user *user;
    size_t resultlen;
    char *identifier, *alttext, *result, *symbol, *prefix;

    identifier = strdup(code);
    alttext = strchr(identifier, '|');
    if (alttext)
        *alttext++ = '\0';

    switch (identifier[0])
    {
        case '#': /* channel */
            if (alttext)
            {
                prefix = (char*)"#";
                symbol = strdup(alttext);
            }
            else
            {
                channel = account->channels.find(identifier+1);
                if (channel != account->channels.end())
                {
                    prefix = (char*)"#";
                    symbol = strdup(channel->second.name.data());
                }
                else
                {
                    prefix = (char*)"Channel:";
                    symbol = strdup(identifier+1);
                }
            }
            break;
        case '@': /* user */
            if (alttext)
            {
                prefix = (char*)"@";
                symbol = strdup(alttext);
            }
            else
            {
                user = weechat::user::search(account, identifier+1);
                if (user)
                {
                    prefix = (char*)"@";
                    symbol = strdup(user->profile.display_name);
                }
                else
                {
                    prefix = (char*)"User:";
                    symbol = strdup(identifier+1);
                }
            }
            break;
        case '!': /* special */
            if (alttext)
            {
                prefix = (char*)"@";
                symbol = strdup(alttext);
            }
            else
            {
                prefix = (char*)"@";
                symbol = strdup(identifier+1);
            }
            break;
        default: /* url */
            prefix = (char*)"";
            symbol = strdup(code);
            break;
    }

    free(identifier);
    resultlen = snprintf(NULL, 0, "%s%s%s%s", weechat_color("chat_nick"), prefix, symbol, weechat_color("reset")) + 1;
    result = (char*)malloc(resultlen);
    snprintf(result, resultlen, "%s%s%s%s", weechat_color("chat_nick"), prefix, symbol, weechat_color("reset"));
    free(symbol);

    return result;
}

void message__htmldecode(char *dest, const char *src, size_t n)
{
    size_t i, j;

    for (i = 0, j = 0; i < n; i++, j++)
        switch (src[i])
        {
            case '\0':
                dest[j] = '\0';
                return;
            case '&':
                if (src[i+1] == 'g' &&
                    src[i+2] == 't' &&
                    src[i+3] == ';')
                {
                    dest[j] = '>';
                    i += 3;
                    break;
                }
                else if (src[i+1] == 'l' &&
                         src[i+2] == 't' &&
                         src[i+3] == ';')
                {
                    dest[j] = '<';
                    i += 3;
                    break;
                }
                else if (src[i+1] == 'a' &&
                         src[i+2] == 'm' &&
                         src[i+3] == 'p' &&
                         src[i+4] == ';')
                {
                    dest[j] = '&';
                    i += 4;
                    break;
                }
                /* fallthrough */
            default:
                dest[j] = src[i];
                break;
        }
    dest[j-1] = '\0';
    return;
}

char *message__decode(weechat::account *account,
                           const char *text)
{
    int rc;
    regex_t reg;
    regmatch_t groups[max_groups];
    char msgbuf[100];
    char *decoded_text;
    const char *cursor;
    size_t offset;

    if ((rc = regcomp(&reg, format_regex, REG_EXTENDED)))
    {
        regerror(rc, &reg, msgbuf, sizeof(msgbuf));
        weechat_printf(
            account->buffer,
            _("%s%s: error compiling message formatting regex: %s"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME,
            msgbuf);
        return strdup(text);
    }

    decoded_text = (char*)malloc(MESSAGE_MAX_LENGTH);
    if (!decoded_text)
    {
        regfree(&reg);
        weechat_printf(
            account->buffer,
            _("%s%s: error allocating space for message"),
            weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
        return strdup(text);
    }
    decoded_text[0] = '\0';

    for (cursor = text; regexec(&reg, cursor, max_groups, groups, 0) == 0; cursor += offset)
    {
        offset = groups[0].rm_eo;

        char *copy = strdup(cursor);
        if (!copy)
        {
            regfree(&reg);
            free(decoded_text);
            weechat_printf(
                account->buffer,
                _("%s%s: error allocating space for message"),
                weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
            return strdup(text);
        }
        copy[groups[1].rm_eo] = '\0';

        char *match = strdup(copy + groups[1].rm_so);
        if (!match)
        {
            free(copy);
            regfree(&reg);
            free(decoded_text);
            weechat_printf(
                account->buffer,
                _("%s%s: error allocating space for message"),
                weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
            return strdup(text);
        }
        copy[groups[0].rm_so] = '\0';

        char *prematch = strdup(copy);
        if (!prematch)
        {
            free(match);
            free(copy);
            regfree(&reg);
            free(decoded_text);
            weechat_printf(
                account->buffer,
                _("%s%s: error allocating space for message"),
                weechat_prefix("error"), WEECHAT_XMPP_PLUGIN_NAME);
            return strdup(text);
        }
        free(copy);

        strncat(decoded_text, prematch,
                MESSAGE_MAX_LENGTH - strlen(decoded_text) - 1);
        free(prematch);

        char *replacement = message__translate_code(account, match);
        free(match);

        strncat(decoded_text, replacement,
                MESSAGE_MAX_LENGTH - strlen(decoded_text) - 1);
        free(replacement);
    }
    strncat(decoded_text, cursor,
            MESSAGE_MAX_LENGTH - strlen(decoded_text) - 1);

    message__htmldecode(decoded_text, decoded_text,
                             MESSAGE_MAX_LENGTH);

    regfree(&reg);
    return decoded_text;
}
