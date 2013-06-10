//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Command-line arguments parser.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CMDLINE_PARSER_H
#define CMDLINE_PARSER_H
//------------------------------------------------------------------------------
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include <getopt.h>

#include "../auxiliary/exception.h"
//------------------------------------------------------------------------------
using namespace NST::auxiliary;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
namespace cmdline
{

class CLIError : public Exception
{
public:
    explicit CLIError(const std::string& msg)
        : Exception(msg) { }
};

struct Opt
{
    class Value
    {
    public:
        Value(const char* const v) : value(v)
        {
        }

        operator const char*() const { return value; }
        operator std::string() const { return std::string(value); }
        int           to_int() const { return atoi(value); }
        bool         to_bool() const { return std::string(value) == "true"; }

    private:
        const char* const value;
    };

    enum Type
    {
        NO       = no_argument,
        REQUIRED = required_argument,
        OPTIONAL = optional_argument, // not yet supported
    };

    const char short_opt;   // a character for short option, can be 0
    const char* long_opt;   // a string long option, can be NULL
    const Type type;
    const char* deflt;      // default value
    const char* description;
    const char* value_pattern;
    const char* value;
    bool passed;            // is option parsed
};


template <typename CLI>
class CmdlineParser
{
public:
    CmdlineParser() {}
    ~CmdlineParser() {}

    void parse(int argc, char** argv) throw (CLIError);
    void validate();

    const Opt::Value operator[](typename CLI::Names name) const
    {
        return Opt::Value(CLI::options[name].value);
    }

    bool is_passed(typename CLI::Names name) const
    {
        return CLI::options[name].passed;
    }

    bool is_default(typename CLI::Names name) const
    {
        const Opt& a = CLI::options[name];
        return a.value == a.deflt;
    }

    static void print_usage(std::ostream& out, const char* executable);

private:
    void set_value(int index) const
    {
        Opt& a = CLI::options[index];
        // if option argument specified (by global optarg) - set it
        // otherwise set valid default OR "true" for no-args options
        a.value = optarg ? optarg : (a.deflt && a.type != Opt::NO ? a.deflt : "true");
        a.passed = true;
    }

    std::string build_name(char short_name, const std::string& long_name) const
    {
       return std::string("\'") +
              (short_name ? std::string("-") + char(short_name) : long_name) + '\'';
    }

    int short_opt_index(char c) const
    {
        for(int i = 0; i < CLI::num; ++i)
        {
            if(CLI::options[i].short_opt == c)
            {
                return i;
            }
        }
        return -1;
    }

    // making class noncopyable
    CmdlineParser(const CmdlineParser &parser);
    const CmdlineParser& operator=(const CmdlineParser &parser);
};

template <typename CLI>
void CmdlineParser<CLI>::parse(int argc, char** argv) throw (CLIError)
{
    // generate input data for getopt_long()
    option long_opts[CLI::num + 1]; // +1 for NULL-option
    char short_opts[CLI::num * 2 + 2] = {0};

    short_opts[0] = ':';

    char *short_p = &short_opts[1];
    for (int i = 0; i < CLI::num; ++i)
    {
        const Opt& a = CLI::options[i];

        long_opts[i].name    = a.long_opt;
        long_opts[i].has_arg = a.type;
        long_opts[i].flag    = 0;
        long_opts[i].val     = 0;

/*
    The FreeBSD doesn't support GNU extension for optional arguments of short options,
    like "i::", see:
    http://www.unix.com/man-page/freebsd/3/getopt/
    http://www.unix.com/man-page/FreeBSD/3/getopt_long/
*/
        if(a.short_opt)
        {
            *short_p = a.short_opt;
            ++short_p;
            if(a.type == Opt::REQUIRED)
            {
                *short_p = ':'; // argument to option is required
                ++short_p;
            }
        }
    }

    // fill last element
    memset(&long_opts[CLI::num], 0, sizeof(long_opts[CLI::num]));

    // assuming that argc and argv are the same as those passed to program
    int opt = 0;
    int opt_index = 0;

    while(true)
    {
        opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index);
        if(opt == -1)
        {
            break;
        }

        switch(opt)
        {
        case 0:
            // store long option
            set_value(opt_index);
            break;

        case '?':
        {
            std::string unkn = build_name(optopt, std::string(argv[optind - 1]));
            throw CLIError(std::string("unrecognized option: ") + unkn);
        }

        case ':':
        {
            std::string miss = build_name(optopt, std::string(argv[optind - 1]));
            throw CLIError(std::string("option requires an argument: ") + miss);
        }

        default:
        {
            // if short option found
            int index = short_opt_index(opt);
            if(index != -1)
            {
                set_value(index);
            }
            break;
        }
        }
    }

    // if we get non-option element in args, throw exception
    if(optind != argc)
    {
        // quote non-option
        std::string name = build_name(0, std::string(argv[optind]));
        throw CLIError(std::string("unexpected operand on command line: ")
                + name);
    }

    // set default values
    for(int i = 0; i < CLI::num; ++i)
    {
        Opt& a = CLI::options[i];
        if(a.value == NULL) // is value still uninitialized?
        {
            if(a.deflt) // try to substitute by default value
            {
                a.value = a.deflt;
                a.passed = false;
            }
        }
    }
}

template <typename CLI>
void CmdlineParser<CLI>::validate()
{
    // validate Args::arguments[i].value. NULL isn't valid!
    for(int i = 0; i < CLI::num; ++i)
    {
        Opt& a = CLI::options[i];
        if(a.value == NULL) // is value still uninitialized?
        {
            std::string long_opt = a.long_opt ? std::string("--") + a.long_opt : "";
            std::string name = build_name(a.short_opt, long_opt);
            throw CLIError(std::string("Missing required option: ") + name);
        }
    }
}

template <typename CLI>
void CmdlineParser<CLI>::print_usage(std::ostream& out, const char* name)
{
    out << "Usage: " << name << " [OPTIONS]..." << std::endl;

    for(int i = 0; i < CLI::num; ++i)
    {
        const Opt& a = CLI::options[i];
        std::string s_opt;
        std::string l_opt;
        std::string text;

        if(a.short_opt != 0)
        {
            char tmp[] = { '-', a.short_opt, ' ', '\0' };
            if(a.long_opt) tmp[2] = ',';
            s_opt = std::string("   ") + tmp; //indentation
        }
        if(a.long_opt)
        {
            l_opt = std::string(" --") + std::string(a.long_opt);

            if(a.value_pattern)
            {
                l_opt += '=';
                l_opt += a.value_pattern;
            }
        }
        if(a.deflt) // has default value?
        {
            text = std::string("(default:") + a.deflt + ") ";
        }
        else
        {
            text = "(required) ";
        }

        if(a.description)
        {
            text += a.description;
        }

        out << std::setw(6) << s_opt;
        out << std::setiosflags(std::ios::left) << std::setw(25) << l_opt;
        /* don't wrap text description
        while(text.size() > 49) // wrap text at 80'th character
        {
            out << text.substr(0, 49) << std::endl;
            out << std::string(80 - 49, ' ');
            text = text.substr(49);
        }*/
        out << text << std::endl;
    }
}

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMDLINE_PARSER_H
//------------------------------------------------------------------------------
