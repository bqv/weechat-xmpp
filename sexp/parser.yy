%skeleton "lalr1.cc"
%require "3.0"
%debug
%defines

%define api.namespace {sexp}
%define api.parser.class {parser}

%code requires{
    namespace sexp {
        class driver;
        class scanner;
    }
}

%parse-param { sexp::scanner &scanner  }
%parse-param { sexp::driver  &driver  }

%code{
    #include <iostream>
    #include <cstdlib>
    #include <sstream>

    /* include for all driver functions */
    #include "driver.hh"

    #undef yylex
    #define yylex scanner.yylex
}

%define api.value.type variant
%define parse.assert
%define parse.error verbose

%token               END    0     "end of file"
%token               LPAREN
%token               RPAREN
%token <std::string> NAME
%token <std::string> STRING
%token               SPACE

%locations

%start input

%%
input : ws END | element input;

element : lparen attributeset rparenq
        | lparen tag children rparen;

ws : | gap;
gap : SPACE;

lparen : ws LPAREN;
rparen : ws RPAREN { driver.end_tag(); };
rparenq : ws RPAREN;

tag : ws NAME { driver.start_tag($2); }
    | ws NAME ':' NAME { driver.start_tag($4); };

attributeset : '@' attributes;

attributes : ws | gap attribute attributes;

attribute : lparen ws NAME gap STRING rparenq { driver.add_attr($3, $5); };

children : ws
         | gap STRING children { driver.add_text($2); }
         | gap element children;
%%

void sexp::parser::error(const sexp::parser::location_type &l, const std::string &err_message)
{
    std::ostringstream ss;
    ss << "parsing " << err_message << " at " << l;
    throw std::invalid_argument(ss.str());
}
