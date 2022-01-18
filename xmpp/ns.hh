// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <string_view>

class xmlns {
private:
    const char *const _uri;
protected:
    inline xmlns(const char *uri) : _uri(uri) {}
public:
    inline const char *ns() { return _uri; }
    inline operator const char *() { return _uri; }
};

struct etherx_jabber_org {
    struct streams : public xmlns { streams() : xmlns("http://etherx.jabber.org/streams") {} };
};
struct jabber_org {
    struct features {
        struct amp : public xmlns { amp() : xmlns("http://jabber.org/features/amp") {} };
        struct compress : public xmlns { compress() : xmlns("http://jabber.org/features/compress") {} };
    };
    struct protocol {
        struct activity : public xmlns { activity() : xmlns("http://jabber.org/protocol/activity") {} };
        struct address : public xmlns { address() : xmlns("http://jabber.org/protocol/address") {} };
        struct amp : public xmlns { amp() : xmlns("http://jabber.org/protocol/amp") {}
            struct errors : public xmlns { errors() : xmlns("http://jabber.org/protocol/amp#errors") {} };
        };
        struct bytestreams : public xmlns { bytestreams() : xmlns("http://jabber.org/protocol/bytestreams") {} };
        struct caps : public xmlns { caps() : xmlns("http://jabber.org/protocol/caps") {} };
        struct chatstates : public xmlns { chatstates() : xmlns("http://jabber.org/protocol/chatstates") {} };
        struct commands : public xmlns { commands() : xmlns("http://jabber.org/protocol/commands") {} };
        struct compress : public xmlns { compress() : xmlns("http://jabber.org/protocol/compress") {}
            struct exi : public xmlns { exi() : xmlns("http://jabber.org/protocol/compress/exi") {} };
        };
        struct disco {
            struct info : public xmlns { info() : xmlns("http://jabber.org/protocol/disco#info") {} };
            struct items : public xmlns { items() : xmlns("http://jabber.org/protocol/disco#items") {} };
        };
        struct feature_neg : public xmlns { feature_neg() : xmlns("http://jabber.org/protocol/feature-neg") {} };
        struct files : public xmlns { files() : xmlns("http://jabber.org/protocol/files") {} };
        struct geoloc : public xmlns { geoloc() : xmlns("http://jabber.org/protocol/geoloc") {} };
        struct http_auth : public xmlns { http_auth() : xmlns("http://jabber.org/protocol/http-auth") {} };
        struct httpbind : public xmlns { httpbind() : xmlns("http://jabber.org/protocol/httpbind") {} };
        struct ibb : public xmlns { ibb() : xmlns("http://jabber.org/protocol/ibb") {} };
        struct jinglenodes : public xmlns { jinglenodes() : xmlns("http://jabber.org/protocol/jinglenodes") {} };
        struct mood : public xmlns { mood() : xmlns("http://jabber.org/protocol/mood") {} };
        struct muc : public xmlns { muc() : xmlns("http://jabber.org/protocol/muc") {}
            struct admin : public xmlns { admin() : xmlns("http://jabber.org/protocol/muc#admin") {} };
            struct owner : public xmlns { owner() : xmlns("http://jabber.org/protocol/muc#owner") {} };
            struct unique : public xmlns { unique() : xmlns("http://jabber.org/protocol/muc#unique") {} };
            struct user : public xmlns { user() : xmlns("http://jabber.org/protocol/muc#user") {} };
        };
        struct nick : public xmlns { nick() : xmlns("http://jabber.org/protocol/nick") {} };
        struct offline : public xmlns { offline() : xmlns("http://jabber.org/protocol/offline") {} };
        struct physloc : public xmlns { physloc() : xmlns("http://jabber.org/protocol/physloc") {} };
        struct poke : public xmlns { poke() : xmlns("http://jabber.org/protocol/poke") {} };
        struct pubsub : public xmlns { pubsub() : xmlns("http://jabber.org/protocol/pubsub") {}
            struct errors : public xmlns { errors() : xmlns("http://jabber.org/protocol/pubsub#errors") {} };
            struct event : public xmlns { event() : xmlns("http://jabber.org/protocol/pubsub#event") {} };
            struct owner : public xmlns { owner() : xmlns("http://jabber.org/protocol/pubsub#owner") {} };
        };
        struct rosterx : public xmlns { rosterx() : xmlns("http://jabber.org/protocol/rosterx") {} };
        struct rsm : public xmlns { rsm() : xmlns("http://jabber.org/protocol/rsm") {} };
        struct shim : public xmlns { shim() : xmlns("http://jabber.org/protocol/shim") {} };
        struct si : public xmlns { si() : xmlns("http://jabber.org/protocol/si") {}
            struct profile {
                struct file_transfer : public xmlns { file_transfer() : xmlns("http://jabber.org/protocol/si/profile/file-transfer") {} };
            };
        };
        struct sipub : public xmlns { sipub() : xmlns("http://jabber.org/protocol/sipub") {} };
        struct soap {
            struct fault : public xmlns { fault() : xmlns("http://jabber.org/protocol/soap#fault") {} };
        };
        struct tune : public xmlns { tune() : xmlns("http://jabber.org/protocol/tune") {} };
        struct waitinglist : public xmlns { waitinglist() : xmlns("http://jabber.org/protocol/waitinglist") {} };
        struct workgroup : public xmlns { workgroup() : xmlns("http://jabber.org/protocol/workgroup") {} };
        struct xdata_layout : public xmlns { xdata_layout() : xmlns("http://jabber.org/protocol/xdata-layout") {} };
        struct xdata_validate : public xmlns { xdata_validate() : xmlns("http://jabber.org/protocol/xdata-validate") {} };
        struct xhtml_im : public xmlns { xhtml_im() : xmlns("http://jabber.org/protocol/xhtml-im") {} };
    };
};
struct jabber {
    struct client : public xmlns { client() : xmlns("jabber:client") {} };
    struct component {
        struct accept : public xmlns { accept() : xmlns("jabber:component:accept") {} };
        struct connect : public xmlns { connect() : xmlns("jabber:component:connect") {} };
    };
    struct iq {
        struct auth : public xmlns { auth() : xmlns("jabber:iq:auth") {} };
        struct gateway : public xmlns { gateway() : xmlns("jabber:iq:gateway") {} };
        struct last : public xmlns { last() : xmlns("jabber:iq:last") {} };
        struct oob : public xmlns { oob() : xmlns("jabber:iq:oob") {} };
        struct pass : public xmlns { pass() : xmlns("jabber:iq:pass") {} };
        struct privacy : public xmlns { privacy() : xmlns("jabber:iq:privacy") {} };
        struct private_ : public xmlns { private_() : xmlns("jabber:iq:private") {} };
        struct register_ : public xmlns { register_() : xmlns("jabber:iq:register") {} };
        struct roster : public xmlns { roster() : xmlns("jabber:iq:roster") {} };
        struct rpc : public xmlns { rpc() : xmlns("jabber:iq:rpc") {} };
        struct search : public xmlns { search() : xmlns("jabber:iq:search") {} };
        struct time : public xmlns { time() : xmlns("jabber:iq:time") {} };
        struct version : public xmlns { version() : xmlns("jabber:iq:version") {} };
    };
    struct server : public xmlns { server() : xmlns("jabber:server") {}
        struct dialback : public xmlns { dialback() : xmlns("jabber:server:dialback") {} };
    };
    struct x {
        struct conference : public xmlns { conference() : xmlns("jabber:x:conference") {} };
        struct data : public xmlns { data() : xmlns("jabber:x:data") {} };
        struct delay : public xmlns { delay() : xmlns("jabber:x:delay") {} };
        struct encrypted : public xmlns { encrypted() : xmlns("jabber:x:encrypted") {} };
        struct event : public xmlns { event() : xmlns("jabber:x:event") {} };
        struct expire : public xmlns { expire() : xmlns("jabber:x:expire") {} };
        struct oob : public xmlns { oob() : xmlns("jabber:x:oob") {} };
        struct roster : public xmlns { roster() : xmlns("jabber:x:roster") {} };
        struct signed_ : public xmlns { signed_() : xmlns("jabber:x:signed") {} };
    };
};
struct roster {
    struct delimiter : public xmlns { delimiter() : xmlns("roster:delimiter") {} };
};
struct storage {
    struct bookmarks : public xmlns { bookmarks() : xmlns("storage:bookmarks") {} };
    struct metacontacts : public xmlns { metacontacts() : xmlns("storage:metacontacts") {} };
    struct pubsubs : public xmlns { pubsubs() : xmlns("storage:pubsubs") {} };
    struct rosternotes : public xmlns { rosternotes() : xmlns("storage:rosternotes") {} };
};
struct urn {
    struct ietf {
        struct params {
            struct xml {
                struct ns {
                    struct xmpp_bind : public xmlns { xmpp_bind() : xmlns("urn:ietf:params:xml:ns:xmpp-bind") {} };
                    struct xmpp_e2e : public xmlns { xmpp_e2e() : xmlns("urn:ietf:params:xml:ns:xmpp-e2e") {} };
                    struct xmpp_sasl : public xmlns { xmpp_sasl() : xmlns("urn:ietf:params:xml:ns:xmpp-sasl") {} };
                    struct xmpp_session : public xmlns { xmpp_session() : xmlns("urn:ietf:params:xml:ns:xmpp-session") {} };
                    struct xmpp_stanzas : public xmlns { xmpp_stanzas() : xmlns("urn:ietf:params:xml:ns:xmpp-stanzas") {} };
                    struct xmpp_streams : public xmlns { xmpp_streams() : xmlns("urn:ietf:params:xml:ns:xmpp-streams") {} };
                    struct xmpp_tls : public xmlns { xmpp_tls() : xmlns("urn:ietf:params:xml:ns:xmpp-tls") {} };
                };
            };
        };
    };
    struct xmpp {
        struct ago { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:ago:0") {} }; };
        struct archive : public xmlns { archive() : xmlns("urn:xmpp:archive") {} };
        struct attention { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:attention:0") {} }; };
        struct avatar {
            struct data : public xmlns { data() : xmlns("urn:xmpp:avatar:data") {} };
            struct metadata : public xmlns { metadata() : xmlns("urn:xmpp:avatar:metadata") {} };
        };
        struct bidi : public xmlns { bidi() : xmlns("urn:xmpp:bidi") {} };
        struct blocking : public xmlns { blocking() : xmlns("urn:xmpp:blocking") {}
            struct errors : public xmlns { errors() : xmlns("urn:xmpp:blocking:errors") {} };
        };
        struct bob : public xmlns { bob() : xmlns("urn:xmpp:bob") {} };
        struct bookmarks { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:bookmarks:1") {} }; };
        struct browsing { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:browsing:0") {} }; };
        struct bxmpp : public xmlns { bxmpp() : xmlns("urn:xmpp:bxmpp") {} };
        struct caps : public xmlns { caps() : xmlns("urn:xmpp:caps") {} };
        struct captcha : public xmlns { captcha() : xmlns("urn:xmpp:captcha") {} };
        struct carbons { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:carbons:2") {} }; };
        struct chatting { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:chatting:0") {} }; };
        struct cmr { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:cmr:0") {} }; };
        struct component { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:component:0") {} }; };
        struct decloak { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:decloak:0") {} }; };
        struct delay : public xmlns { delay() : xmlns("urn:xmpp:delay") {} };
        struct delegation { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:delegation:2") {} }; };
        struct domain_based_name { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:domain-based-name:1") {} }; };
        struct dox { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:dox:0") {} }; };
        struct eventlog : public xmlns { eventlog() : xmlns("urn:xmpp:eventlog") {} };
        struct extdisco { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:extdisco:2") {} }; };
        struct features {
            struct rosterver : public xmlns { rosterver() : xmlns("urn:xmpp:features:rosterver") {} };
        };
        struct forward { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:forward:0") {} }; };
        struct gaming { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:gaming:0") {} }; };
        struct hashes { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:hashes:2") {} }; };
        struct http : public xmlns { http() : xmlns("urn:xmpp:http") {}
            struct upload { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:http:upload:0") {} }; };
        };
        struct idle { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:idle:1") {} }; };
        struct incident { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:incident:2") {} }; };
        struct invisible { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:invisible:1") {} }; };
        struct iot {
            struct concentrators : public xmlns { concentrators() : xmlns("urn:xmpp:iot:concentrators") {} };
            struct control : public xmlns { control() : xmlns("urn:xmpp:iot:control") {} };
            struct discovery : public xmlns { discovery() : xmlns("urn:xmpp:iot:discovery") {} };
            struct provisioning : public xmlns { provisioning() : xmlns("urn:xmpp:iot:provisioning") {} };
            struct sensordata : public xmlns { sensordata() : xmlns("urn:xmpp:iot:sensordata") {} };
        };
        struct jid { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jid:0") {} }; };
        struct jingle { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:1") {} };
            struct apps {
                struct dtls { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:apps:dtls:0") {} }; };
                struct rtp { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:apps:rtp:1") {} };
                    struct errors { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:apps:rtp:errors:1") {} }; };
                    struct info { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:apps:rtp:info:1") {} }; };
                    struct rtcp_fb { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:apps:rtp:rtcp-fb:0") {} }; };
                    struct rtp_hdrext { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:apps:rtp:rtp-hdrext:0") {} }; };
                    struct ssma { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:apps:rtp:ssma:0") {} }; };
                    struct zrtp { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:apps:rtp:zrtp:1") {} }; };
                };
                struct xmlstream { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:apps:xmlstream:0") {} }; };
            };
            struct dtmf { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:dtmf:0") {} }; };
            struct errors { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:errors:1") {} }; };
            struct transfer { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:transfer:0") {} }; };
            struct transports {
                struct dtls_sctp { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:transports:dtls-sctp:1") {} }; };
                struct ibb { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:transports:ibb:1") {} }; };
                struct ice { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:transports:ice:0") {} }; };
                struct ice_udp { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:transports:ice-udp:1") {} }; };
                struct raw_udp { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:transports:raw-udp:1") {} }; };
                struct s5b { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle:transports:s5b:1") {} }; };
                struct webrtc_datachannel { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:jingle:transports:webrtc-datachannel:0") {} }; };
            };
        };
        struct jingle_message { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jingle-message:1") {} }; };
        struct jinglepub { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:jinglepub:1") {} }; };
        struct json { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:json:0") {} }; };
        struct keepalive { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:keepalive:0") {} }; };
        struct langtrans : public xmlns { langtrans() : xmlns("urn:xmpp:langtrans") {}
            struct items : public xmlns { items() : xmlns("urn:xmpp:langtrans:items") {} };
        };
        struct locationquery { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:locationquery:0") {} }; };
        struct media_element : public xmlns { media_element() : xmlns("urn:xmpp:media-element") {} };
        struct message_attaching { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:message-attaching:1") {} }; };
        struct message_correct { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:message-correct:0") {} }; };
        struct message_moderate { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:message-moderate:0") {} }; };
        struct message_retract { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:message-retract:0") {} }; };
        struct muc {
            struct conditions { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:muc:conditions:1") {} }; };
        };
        struct omemo { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:omemo:2") {} }; };
        struct order_by { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:order-by:1") {} }; };
        struct pie { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:pie:0") {} }; };
        struct ping : public xmlns { ping() : xmlns("urn:xmpp:ping") {} };
        struct privilege { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:privilege:1") {} }; };
        struct reach { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:reach:0") {} }; };
        struct receipts : public xmlns { receipts() : xmlns("urn:xmpp:receipts") {} };
        struct reputation { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:reputation:0") {} }; };
        struct sec_label { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:sec-label:0") {} };
            struct catalog { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:sec-label:catalog:2") {} }; };
            struct ess { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:sec-label:ess:0") {} }; };
        };
        struct sic { struct _1 : public xmlns { _1() : xmlns("urn:xmpp:sic:1") {} }; };
        struct sift { struct _2 : public xmlns { _2() : xmlns("urn:xmpp:sift:2") {} }; };
        struct sm { struct _3 : public xmlns { _3() : xmlns("urn:xmpp:sm:3") {} }; };
        struct spoiler { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:spoiler:0") {} }; };
        struct thumbs { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:thumbs:0") {} }; };
        struct time : public xmlns { time() : xmlns("urn:xmpp:time") {} };
        struct tmp {
            struct abuse : public xmlns { abuse() : xmlns("urn:xmpp:tmp:abuse") {} };
            struct io_data : public xmlns { io_data() : xmlns("urn:xmpp:tmp:io-data") {} };
            struct mine { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:tmp:mine:0") {} }; };
            struct profile : public xmlns { profile() : xmlns("urn:xmpp:tmp:profile") {} };
            struct roster_management { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:tmp:roster-management:0") {} }; };
        };
        struct viewing { struct _0 : public xmlns { _0() : xmlns("urn:xmpp:viewing:0") {} }; };
        struct xbosh : public xmlns { xbosh() : xmlns("urn:xmpp:xbosh") {} };
        struct xdata {
            struct dynamic : public xmlns { dynamic() : xmlns("urn:xmpp:xdata:dynamic") {} };
        };
    };
};
struct vcard_temp_filter : public xmlns { vcard_temp_filter() : xmlns("vcard-temp-filter") {} };
struct vcard_temp {
    struct x {
        struct update : public xmlns { update() : xmlns("vcard-temp:x:update") {} };
    };
};
