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
    const char* value;
    const char* description;
    const char* value_pattern;
};


template <typename Args>
class CmdlineParser
{
public:
    explicit CmdlineParser(int argc, char** argv);
    ~CmdlineParser() {}

    const Arg::Value operator[](typename Args::Names name) const
    {
        return Arg::Value(Args::arguments[name].value);
    }

    static void print_usage(std::ostream& out, const char* executable);

private:
    int short_opt_index(char c) const;

    /* making class noncopyable */
    CmdlineParser(const CmdlineParser &parser);
    const CmdlineParser& operator=(const CmdlineParser &parser);

};

template <typename Args>
CmdlineParser<Args>::CmdlineParser(int argc, char** argv)
{
    // generate input data for getopt_long
    option long_opts[Args::num + 1]; // +1 for NULL-option
    char short_opts[Args::num * 3 + 2] = {0};

    short_opts[0] = ':';

    char *short_p = &short_opts[1];
    for (int i = 0; i < Args::num; ++i)
    {
        long_opts[i].name = Args::arguments[i].long_opt;
        long_opts[i].has_arg = Args::arguments[i].type;
        long_opts[i].flag = 0;
        long_opts[i].val = 0;

        if(Args::arguments[i].short_opt)
        {
            *short_p = Args::arguments[i].short_opt;
            ++short_p;
            switch(long_opts[i].has_arg)
            {
            case 1:
                *short_p = ':';
                ++short_p;
                break;
            case 2:
                *short_p = ':';
                ++short_p;
                *short_p = ':';
                ++short_p;
                break;
            default:
                break;
            }
        }
    }
    // fill last element
    memset(&long_opts[Args::num], 0, sizeof(long_opts[Args::num]));

    /* Assuming that argc and argv are the same as those passed to program */
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
            Args::arguments[opt_index].value = optarg ? optarg : "true";
            break;

        case '?':
            {
                std::string failed_opt = optopt? std::string(1, optopt)
                    : std::string(argv[optind - 1]);
                throw Exception(std::string("unrecognized option \'")
                    + failed_opt + std::string("\'\n"));
            }
            break;

        case ':':
            {
                std::string missed_opt = optopt? std::string(1, optopt)
                    : std::string(argv[optind - 1]);
                throw Exception(std::string("missing argument: -- \'")
                    + missed_opt + std::string("\'\n"));
            }
            break;

        default:
            // short opt found
            int index = short_opt_index(opt);
            Args::arguments[index].value = optarg ? optarg : "true";
            break;
        }
    }
}

template <typename Args>
int CmdlineParser<Args>::short_opt_index(char c) const
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

template <typename Args>
void CmdlineParser<Args>::print_usage(std::ostream& out, const char* name)
{
    out << "Usage: " << name << " [OPTION]..." << std::endl;
    out << "Mandatory arguments to long options are "
           "mandatory for short options too." << std::endl;

    for(int i = 0; i < Args::num; ++i)
    {
        const Arg& a = Args::arguments[i];
        std::string s_opt;
        std::string l_opt;
        std::string descr;

        if(a.short_opt != 0)
        {
            char tmp[] = { '-', a.short_opt, ' ', '\0' };
            if(a.long_opt) tmp[2] = ',';
            s_opt = tmp;
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
        if(a.description)
        {
            descr = a.description;
        }

        out << std::setiosflags(std::ios::right) << std::setw(6) << s_opt;
        out << std::resetiosflags(std::ios::adjustfield);
        out << std::setiosflags(std::ios::left) << std::setw(32) << l_opt;
        while(descr.size() > 48)
        {
            out << descr.substr(0, 48) << std::endl;
            descr = descr.substr(48);
        }
        out << descr << std::endl;
    }
}

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMDLINE_PARSER_H
//------------------------------------------------------------------------------
