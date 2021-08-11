// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdio>

#include "strophe.hh"
#include "strophe.ipp"

namespace xmpp {
    extern "C" {
#include <strophe.h>
    }

    context::context(xmpp_ctx_ptr ptr)
        : xmpp_ctx_ptr(std::move(ptr)) {
    }

    context::context(xmpp_ctx_t *ptr)
        : xmpp_ctx_ptr(ptr, xmpp_ctx_free) {
    }

    context::~context() {
        this->reset(nullptr);
    }

    connection::connection(const context& context)
        : connection(xmpp_conn_new(&*context)) {
    }

    connection::connection(xmpp_conn_ptr ptr)
        : xmpp_conn_ptr(std::move(ptr)) {
    }

    connection::connection(xmpp_conn_t *ptr)
        : xmpp_conn_ptr(ptr, xmpp_conn_release) {
    }

    connection::~connection() {
        this->reset(nullptr);
    }

    void shutdown() {
        xmpp_shutdown();
    }
}

namespace xml {
    extern "C" {
#include <libxml/xmlwriter.h>
    }

    template void set_error_context<FILE>(FILE*);

    document::document(std::string_view text)
        : m_ptr(xmlRecoverMemory(text.data(), text.size()))
        , m_size(text.size()) {
    }

    document::~document() {
        xmlFreeDoc(this->m_ptr);
    }

    document::node::node(xmlNodePtr ptr)
        : m_ptr(ptr) {
    }

    std::string document::node::name() const {
        return reinterpret_cast<const char*>(this->m_ptr->name);
    }

    std::optional<const document::node> document::root() {
        xmlNodePtr root = xmlDocGetRootElement(this->m_ptr);
        if (root)
            return document::node(root);
        else
            return {};
    }

    document::operator bool () const {
        return this->m_ptr;
    }

    std::string document::format() const {
        if (!this->m_ptr)
            throw xml::error("failed to parse xml");

        std::unique_ptr<xmlChar> buf(
            new xmlChar[this->m_size * 2]);
        int size = -1;
        xmlChar *bufPtr = &*buf;
        xmlDocDumpFormatMemory(this->m_ptr, &bufPtr, &size, 1);

        return std::string(bufPtr, bufPtr + size);
    }
}
