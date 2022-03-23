#pragma once

#ifndef yyFlexLexer
#include <FlexLexer.h>
#endif

#include "parser.tab.hh"
#include "location.hh"

namespace sexp {

    class scanner : public yyFlexLexer {
    public:

        scanner(std::istream *in) : yyFlexLexer(in)
        {
        };

        virtual ~scanner() {
        };

        // get rid of override virtual function warning
        using FlexLexer::yylex;

        virtual
        int yylex(sexp::parser::semantic_type *const lval,
                  sexp::parser::location_type *location);
        // YY_DECL defined in lexer.l
        // Method body created by flex in lexer.yy.cc


    private:
        /* yyval ptr */
        sexp::parser::semantic_type *yylval = nullptr;
    };

}
