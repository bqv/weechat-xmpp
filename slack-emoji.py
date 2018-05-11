#!/usr/bin/env python3

import requests
import json
import ast

emoji = requests.get("https://raw.githubusercontent.com/iamcal/emoji-data/master/emoji.json").json()

print("""
#include <stdlib.h>

#define MAX_TEXTS %d
#define MAX_NAMES %d

struct t_slack_emoji_by_name {
    const char *name;
    const char *unicode;
    const char *text_to;
    const char *text_from[MAX_TEXTS];
};

struct t_slack_emoji_by_text {
    const char *text;
    const char *unicode;
    const char *name_to;
    const char *name_from[MAX_NAMES];
};
"""%(max(len(o['texts'] if o['texts'] else []) for o in emoji) + 1,
     max(len(o['short_names'] if o['short_names'] else []) for o in emoji) + 1))
print("static struct t_slack_emoji_by_name slack_emoji_by_name[] =")
print("{"+"\n".join(", {{ {0}, {1}, {2}, {3} }}".format(
    json.dumps(name),
    json.dumps(ast.parse("\"\\u"+"\\u".join(o['unified'].split('-'))+"\"", mode='eval').body.s),
    json.dumps(o['text']),
    "{"+json.dumps(o['texts']+[None] if o['texts'] else [None])[1:-1]+"}")
                    for o,name in sorted(((o,name) for o in emoji for name in o['short_names']),
                                         key=lambda x: x[1])
).replace("null", "NULL")[1:])
print("};")
print("")
print("static struct t_slack_emoji_by_text slack_emoji_by_text[] =")
print("{"+"\n".join(", {{ {0}, {1}, {2}, {3} }}".format(
    json.dumps(text),
    json.dumps(ast.parse("\"\\u"+"\\u".join(o['unified'].split('-'))+"\"", mode='eval').body.s),
    json.dumps(o['short_name']),
    "{"+json.dumps(o['short_names']+[None] if o['short_names'] else [None])[1:-1]+"}")
                    for o,text in sorted(((o,text) for o in emoji if o['texts'] for text in o['texts']),
                                         key=lambda x:x[1])
).replace("null", "NULL")[1:])
print("};")
