#pragma once

#include <string>
#include <cstddef>
#include <istream>
#include <vector>

#include <strophe.h>

#include "scanner.hh"
#include "parser.tab.hh"

namespace sexp {

    class driver {
    public:
        driver(xmpp_ctx_t *context) : context(context) {}

        virtual ~driver();

        /**
         * parse - parse from a file
         * @param text - valid string
         */
        bool parse(const char *text, std::ostream *debug);

        /**
         * parse - parse from a c++ input stream
         * @param is - std::istream&, valid input stream
         */
        bool parse(std::istream &iss, std::ostream *debug);

        void start_tag(const std::string &name);
        void end_tag();
        void add_text(const std::string &text);
        void add_attr(const std::string &name, const std::string &value);

        std::vector<xmpp_stanza_t*> elements;

    private:
        bool parse_helper(std::istream &stream, std::ostream *debug);

        xmpp_ctx_t *context;

        std::vector<xmpp_stanza_t*> stack;
        sexp::parser  *parser  = nullptr;
        sexp::scanner *scanner = nullptr;
    };

}
