%option debug
%option nodefault
%option yyclass="sexp::scanner"
%option noyywrap
%option c++

%{
    #include <string>

    #include "scanner.hh"
    #undef  YY_DECL
    #define YY_DECL int sexp::scanner::yylex(sexp::parser::semantic_type *const lval, sexp::parser::location_type *loc)

    using token = sexp::parser::token;

    // defaults to NULL
    #define yyterminate() return token::END

    // update location on matching
    #define YY_USER_ACTION loc->step(); loc->columns(yyleng);
%}

/* Regular Expressions */
%%
%{
                    yylval = lval;
%}

"("                 {
                        return token::LPAREN;
                    }

")"                 {
                        return token::RPAREN;
                    }

[\n \t\r]+          {
                        // Update line number
                        loc->lines();
                        return token::SPACE;
                    }

\"([^"\\]|\\.)*\"   {
                        yylval->build<std::string>(yytext);
                        return token::STRING;
                    }

[^ "(:@)]+          {
                        yylval->build<std::string>(yytext);
                        return token::NAME;
                    }

.                   {
                        return *yytext;
                    }
%%
