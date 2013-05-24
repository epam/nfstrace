//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Command-line arguments parser
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

struct Arg
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
        OPTIONAL = optional_argument,
    };

    char short_opt;
    const char* long_opt;
    Type type;
    const char* deflt;
    const char* description;
    const char* value_pattern;
    const char* value;
};


template <typename Args>
class CmdlineParser
{
public:
    CmdlineParser() {}
    ~CmdlineParser() {}

    void parse(int argc, char** argv) throw (Exception);

    const Arg::Value operator[](typename Args::Names name) const
    {
        return Arg::Value(Args::arguments[name].value);
    }

    static void print_usage(std::ostream& out, const char* executable);

private:
    void set_value(int index)const
    {
        Arg& a = Args::arguments[index];
        // if option argument specified (by global optarg) - set it
        // otherwise set valid default for no-args options OR "true"
        a.value = optarg ? optarg : (a.deflt && a.type != Arg::NO ? a.deflt : "true");
    }

    std::string build_name(char short_name, const std::string& long_name)const
    {
       return std::string("\'") +
              (short_name ? std::string("-") + char(short_name) : long_name) + '\'';
    }

    int short_opt_index(char c) const
    {
        for(int i = 0; i < Args::num; ++i)
        {
            if(Args::arguments[i].short_opt == c)
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

template <typename Args>
void CmdlineParser<Args>::parse(int argc, char** argv) throw (Exception)
{
    // generate input data for getopt_long()
    option long_opts[Args::num + 1]; // +1 for NULL-option
    char short_opts[Args::num * 2 + 2] = {0};

    short_opts[0] = ':';

    char *short_p = &short_opts[1];
    for (int i = 0; i < Args::num; ++i)
    {
        const Arg& a = Args::arguments[i];

        long_opts[i].name    = a.long_opt;
        long_opts[i].has_arg = a.type;
        long_opts[i].flag = 0;
        long_opts[i].val = a.short_opt;

/*
    The FreeBSD doesn't support GNU extension for optional arguments of short options,
    like "i::", see:
    http://www.unix.com/man-page/freebsd/3/getopt/
    http://www.unix.com/man-page/FreeBSD/3/getopt_long/

    We are emulate this behavior, each short option will be marked that its arg is required
*/
        if(a.short_opt)
        {
            *short_p = a.short_opt;
            ++short_p;
            if(a.type != Arg::NO)
            {
                *short_p = ':'; // argument to option is required
                ++short_p;
            }
        }
    }

    // fill last element
    memset(&long_opts[Args::num], 0, sizeof(long_opts[Args::num]));

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
            throw Exception(std::string("Unrecognized option: ") + unkn);
        }

        case ':':
        {
            int i = short_opt_index(optopt);
            Arg& a = Args::arguments[i];
            if(a.type == Arg::NO)
            {
                a.value = "true";
            }
            else
            {
                std::string miss = build_name(optopt, std::string(argv[optind - 1]));
                throw Exception(std::string("Missing argument of: ") + miss);
            }
            break;
        }

        default:
        {
            // store short option
            int index = short_opt_index(opt);
            if(index != -1)
            {
                set_value(index);
            }
            break;
        }
        }
    }

    // validate Args::arguments[i].value. NULL isn't valid!
    for(int i = 0; i < Args::num; ++i)
    {
        Arg& a = Args::arguments[i];
        if(a.value == NULL) // is value still uninitialized?
        {
            if(a.deflt) // try to substitute by default value
            {
                a.value = a.deflt;
            }
            else
            {
                std::string long_opt = a.long_opt ? std::string("--") + a.long_opt : "";
                std::string name = build_name(a.short_opt, long_opt);
                throw Exception(std::string("Missing required option: ") + name);
            }
        }
    }
}

template <typename Args>
void CmdlineParser<Args>::print_usage(std::ostream& out, const char* name)
{
    out << "Usage: " << name << " [OPTIONS]..." << std::endl;

    for(int i = 0; i < Args::num; ++i)
    {
        const Arg& a = Args::arguments[i];
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
            text = std::string("default(")+a.deflt + ") ";
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
        out << std::setiosflags(std::ios::left) << std::setw(32) << l_opt;
        while(text.size() > 42) // wrap text at 80'th character
        {
            out << text.substr(0, 42) << std::endl;
            out << std::string(80-42, ' ');
            text = text.substr(42);
        }
        out << text << std::endl;
    }
}

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMDLINE_PARSER_H
//------------------------------------------------------------------------------
