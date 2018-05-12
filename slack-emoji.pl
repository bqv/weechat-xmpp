#!/usr/bin/perl -l

# This Source Code Form is subject to the terms of the Mozilla Public
# License, version 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

use strict;
use warnings;

use LWP::Simple;
use Data::Dumper;
use JSON qw (decode_json);
use List::Util qw (max);

our ($json, @array);

$json = get('https://raw.githubusercontent.com/iamcal/emoji-data/master/emoji.json');
@array = @{ decode_json($json) };

my $maxtexts = max (map { 1 + @{$_} } (grep defined, map { $_->{'texts'} } @array));
my $maxnames = max (map { 1 + @{$_} } (grep defined, map { $_->{'short_names'} } @array));

print "
// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>

#define MAX_TEXTS $maxtexts
#define MAX_NAMES $maxnames

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
";

print "static struct t_slack_emoji_by_name slack_emoji_by_name[] =";
my $c = '{';
my %byname = map { my $o = $_; map {($_, $o)} @{$o->{'short_names'}} } @array;
my @sortedbyname = sort { $a cmp $b } keys %byname;
foreach my $name (@sortedbyname)
{
    my $_0 = "\":$name:\"";
    my @_1 = split /-/, $byname{$name}->{'unified'};
    my $_1 = "\"";
    foreach my $codepoint (@_1) {
        if (hex $codepoint < 0xA0) { $_1 .= chr hex $codepoint } else { $_1 .= "\\u$codepoint" }
    };
    $_1 .= "\"";
    $_1 =~ tr/A-Za-z/a-za-z/;
    my $_2 = $byname{$name}->{'text'};
    if (defined $_2) { $_2 = "\"$_2\"" } else { $_2 = "NULL" };
    $_2 =~ s/\\/\\\\/g;
    my $_3 = "{";
    foreach my $text (@{$byname{$name}->{'texts'}}) { if (defined $text) { $_3 .= "\"$text\", " } };
    $_3 .= "NULL}";
    $_3 =~ s/\\/\\\\/g;
    print "$c { $_0, $_1, $_2, $_3 }";
    $c = ',';
}
print "};";
print "";
print "static struct t_slack_emoji_by_text slack_emoji_by_text[] =";
$c = '{';
my %bytext = map { my $o = $_; map {($_, $o)} @{$o->{'texts'}} } @array;
my @sortedbytext = sort { $a cmp $b } keys %bytext;
foreach my $text (@sortedbytext)
{
    my $_0 = "\"$text\"";
    $_0 =~ s/\\/\\\\/g;
    my @_1 = split /-/, $bytext{$text}->{'unified'};
    my $_1 = "\"";
    foreach my $codepoint (@_1) {
        if (hex $codepoint < 0xA0) { $_1 .= chr hex $codepoint } else { $_1 .= "\\u$codepoint" }
    };
    $_1 .= "\"";
    $_1 =~ tr/A-Za-z/a-za-z/;
    my $_2 = $bytext{$text}->{'short_name'};
    if (defined $_2) { $_2 = "\":$_2:\"" } else { $_2 = "NULL" };
    my $_3 = "{";
    foreach my $name (@{$bytext{$text}->{'short_names'}}) { if (defined $name) { $_3 .= "\":$name:\", " } };
    $_3 .= "NULL}";
    print "$c { $_0, $_1, $_2, $_3 }";
    $c = ',';
}
print "};";
