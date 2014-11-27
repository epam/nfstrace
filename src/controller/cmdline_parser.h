//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Command-line arguments parser.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef CMDLINE_PARSER_H
#define CMDLINE_PARSER_H
//------------------------------------------------------------------------------
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

#include <getopt.h>
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
namespace cmdline
{

class CLIError : public std::runtime_error
{
public:
    explicit CLIError(const std::string& msg) : std::runtime_error{msg} { }
};

struct Opt
{
    class Value
    {
    public:
        Value(const char* const v) : value{v}{}
        Value(Value&&)                       = default;
        Value(const Value&)                  = delete;
        Value& operator=(const Value&)       = delete;

        operator std::string() const { return std::string{value};           }
        const char*  to_cstr() const { return value;                        }
        int           to_int() const { return atoi(value);                  }
        bool         to_bool() const { return strcmp(value, "true") == 0;   }
        bool is(const char* s) const { return strcmp(value, s) == 0;        }

    private:
        const char*const value;
    };

    enum Type { NOA, REQ, MUL };

    const char short_opt;           // a character for short option, can be 0
    const char* const long_opt;     // a string long option, can be nullptr
    const Type type;
    const char* const deflt;        // default value
    const char* const description;
    const char* value_pattern;
    const char* value;
    bool passed;                    // is option parsed
};


template <typename CLI>
class CmdlineParser
{
public:
    CmdlineParser() = default;
    virtual ~CmdlineParser() = default;
    CmdlineParser(const CmdlineParser&)                  = delete;
    CmdlineParser& operator=(const CmdlineParser&)       = delete;

    void parse(int argc, char** argv);
    void validate();

    static Opt::Value get(typename CLI::Names name)
    {
        return Opt::Value{CLI::options[name].value};
    }

    static bool is_passed(typename CLI::Names name)
    {
        return CLI::options[name].passed;
    }

    static bool is_default(typename CLI::Names name)
    {
        const Opt& a = CLI::options[name];
        return a.value == a.deflt;  // compare pointers
    }

    static void print_usage(std::ostream& out, const char* executable);

private:
    virtual void set_multiple_value(int /*index*/, char *const /*v*/){}

    void set_value(int index, char *const v)
    {
        Opt& a = CLI::options[index];
        // if option argument specified - set it otherwise
        // set valid default OR "true" for no-args options
        a.value = v ? v : (a.deflt && a.type != Opt::Type::NOA ? a.deflt : "true");
        a.passed = true;

        if(a.type == Opt::Type::MUL)
        {
            set_multiple_value(index, v);
        }
    }

    static std::string build_name(char short_name, const std::string& long_name)
    {
        if(short_name)
        {
            return { '\'', '-', short_name, '\'' };
        }
        return std::string{'\''} + long_name + '\'';
    }

    static int short_opt_index(const char c)
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
};

template <typename CLI>
void CmdlineParser<CLI>::parse(int argc, char** argv)
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
        long_opts[i].has_arg = (a.type == Opt::Type::NOA) ? no_argument : required_argument;
        long_opts[i].flag    = 0;
        long_opts[i].val     = 0;

        if(a.short_opt)
        {
            *short_p = a.short_opt;
            ++short_p;
            if(a.type != Opt::Type::NOA)
            {
                *short_p = ':'; // argument to option is required
                ++short_p;
            }
        }
    }

    // fill last element
    memset(&long_opts[CLI::num], 0, sizeof(long_opts[CLI::num]));

    // assuming that argc and argv are the same as those passed to program
    int opt_index = 0;

    while(true)
    {
        int opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index);
        if(opt == -1)
        {
            break;
        }

        switch(opt)
        {
        case 0:
            // store long option
            set_value(opt_index, optarg);
            break;

        case '?':
        {
            std::string unkn{ build_name(optopt, argv[optind-1]) };
            throw CLIError{std::string{"Unrecognized option: "} + unkn};
        }

        case ':':
        {
            std::string miss{ build_name(optopt, argv[optind-1]) };
            throw CLIError{std::string{"Option requires an argument: "} + miss};
        }

        default:
        {
            // if short option found
            const int index = short_opt_index(opt);
            if(index != -1)
            {
                set_value(index, optarg);
            }
        }
        }
    }

    // if we get non-option element in args, throw exception
    if(optind != argc)
    {
        // quote non-option
        std::string name{ build_name(0, argv[optind]) };
        throw CLIError{std::string{"Unexpected operand on command line: "}
                + name};
    }

    // set default values
    for(Opt& o : CLI::options)
    {
        if(o.value == nullptr  // is value still uninitialized?
        && o.deflt != nullptr) // try to substitute by default value
        {
            o.value = o.deflt;
            o.passed = false;
        }
    }
}

template <typename CLI>
void CmdlineParser<CLI>::validate()
{
    // validate Args::arguments[i].value. nullptr isn't valid!
    for(const Opt& o : CLI::options)
    {
        if(o.value == nullptr) // is value still uninitialized?
        {
            std::string lopt{ o.long_opt ? std::string("--") + o.long_opt : ""};
            std::string name{ build_name(o.short_opt, lopt) };
            throw CLIError{std::string{"Missing required option: "} + name};
        }
    }
}

template <typename CLI>
void CmdlineParser<CLI>::print_usage(std::ostream& out, const char* name)
{
    out << "Usage: " << name << " [OPTIONS]..." << std::endl;

    for(const Opt& o : CLI::options)
    {
        std::string s_opt;
        std::string l_opt;
        std::string text;

        if(o.short_opt) // print out short key
        {
            char tmp[]{ '-', o.short_opt, ' ', '\0' };
            if(o.long_opt) tmp[2] = ',';
            s_opt = std::string{"   "} + tmp; //indentation
        }
        if(o.long_opt) // print out long key
        {
            l_opt = std::string{" --"} + o.long_opt;

            if(o.value_pattern)
            {
                l_opt += '=';
                l_opt += o.value_pattern;
            }
        }
        if(o.deflt) // has default value?
        {
            text = std::string{"(default:"} + o.deflt + ") ";
        }
        else
        {
            text = "(required) ";
        }

        if(o.description)
        {
            text += o.description;
        }

        out << std::setw(6) << s_opt
            << std::setiosflags(std::ios::left) << std::setw(35) << l_opt
            << text << std::endl;
    }
}

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif//CMDLINE_PARSER_H
//------------------------------------------------------------------------------
