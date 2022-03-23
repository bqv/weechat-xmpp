#include <cctype>
#include <sstream>
#include <cassert>
#include <exception>

#include "driver.hh"

sexp::driver::~driver()
{
    delete(scanner);
    scanner = nullptr;
    delete(parser);
    parser = nullptr;
}

bool sexp::driver::parse(const char *text, std::ostream *debug = nullptr)
{
    assert(text != nullptr);
    std::istringstream stream{std::string(text)};
    return parse(stream, debug);
}

bool sexp::driver::parse(std::istream &stream, std::ostream *debug = nullptr)
{
    if(!stream.good() && stream.eof())
    {
        return false;
    }
    return parse_helper(stream, debug);
}


bool sexp::driver::parse_helper(std::istream &stream, std::ostream *debug)
{
    delete(scanner);
    try
    {
        scanner = new sexp::scanner(&stream);
    }
    catch(std::bad_alloc &ba)
    {
        throw std::runtime_error("Failed to allocate scanner");
    }

    delete(parser);
    try
    {
        parser = new sexp::parser((*scanner) /* scanner */,
                                  (*this) /* driver */);
    }
    catch(std::bad_alloc &ba)
    {
        throw std::runtime_error("Failed to allocate parser");
    }

    const int accept = 0;
    if (debug)
    {
        parser->set_debug_level(1);
        parser->set_debug_stream(*debug);
    }
    return parser->parse() == accept;
}

void sexp::driver::start_tag(const std::string &name)
{
    auto *stanza = xmpp_stanza_new(context);
    xmpp_stanza_set_name(stanza, name.data());
    stack.push_back(stanza);
}

void sexp::driver::end_tag()
{
    auto *stanza = stack.back();
    stack.pop_back();
    if (stack.empty())
        elements.push_back(stanza);
    else
        xmpp_stanza_add_child_ex(stack.back(), stanza, false);
}

void sexp::driver::add_text(const std::string &text)
{
    auto *stanza = xmpp_stanza_new(context);
    xmpp_stanza_set_text(stanza, text.substr(1,text.length()-2).data());
    xmpp_stanza_add_child_ex(stack.back(), stanza, false);
}

void sexp::driver::add_attr(const std::string &name, const std::string &value)
{
    xmpp_stanza_set_attribute(stack.back(), name.data(),
            value.substr(1,value.length()-2).data());
}
