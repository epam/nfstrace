//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class provides validation and access to application parameters
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <sstream>

#include <unistd.h>

#include "cmdline_args.h"
#include "cmdline_parser.h"
#include "parameters.h"
#include "../analyzer/plugin.h"
//------------------------------------------------------------------------------
typedef NST::controller::cmdline::Args CLI;
typedef NST::controller::cmdline::CmdlineParser<CLI> Parser;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
static Parser parser;

Parameters* Parameters::global = NULL;

Parameters::Parameters(int argc, char** argv) : rpc_message_limit(0)
{
    if(global != NULL) return; // init global instance only once

    parser.parse(argc, argv);
    if(parser[CLI::HELP].begin()->to_bool())
    {
        parser.print_usage(std::cout, argv[0]);
        const std::vector<AParams> v = analyzers();

        for(unsigned int i=0; i < v.size(); ++i)
        {
            try
            {
                NST::analyzer::PluginUsage usage(v[i].path);
                std::cout << "Usage of " << v[i].path << ":\n" << usage.get() << std::endl;
            }
            catch(Exception& e)
            {
                std::cout << e.what() << std::endl;
            }
        }
        return;
    }
    parser.validate();

    // cashed values
    const std::string program_path(argv[0]);
    size_t found = program_path.find_last_of("/\\");
    program = program_path.substr(found+1);

    const int limit = parser[CLI::MSIZE].begin()->to_int();
    if(limit < 1 || limit > 4000)
    {
        throw cmdline::CLIError(std::string("Invalid limit of RPC messages: ") + parser[CLI::MSIZE].begin()->to_cstr());
    }

    rpc_message_limit = limit;

    global = this;
}

const std::string& Parameters::program_name() const
{
    return program;
}

RunningMode Parameters::running_mode() const
{
    const std::string mode = *parser[CLI::MODE].begin();
    if(mode == CLI::profiling_mode)
    {
        return Profiling;
    }
    else if(mode == CLI::dumping_mode)
    {
        return Dumping;
    }
    else if(mode == CLI::analysis_mode)
    {
        return Analysis;
    }

    throw cmdline::CLIError(std::string("Unknown mode: ") + mode);
}

bool Parameters::is_verbose() const
{
    return parser[CLI::VERBOSE].begin()->to_bool();
}

const std::string Parameters::interface() const
{
    const std::string itf(*parser[CLI::INTERFACE].begin());

    if(itf.empty())
    {
        const char* mode = parser[CLI::MODE].begin()->to_cstr();
        throw cmdline::CLIError(std::string("interface is required for ") + mode + " mode");
    }

    return itf;
}

unsigned short Parameters::snaplen() const
{
    return parser[CLI::SNAPLEN].begin()->to_int();
}

const std::string Parameters::filter() const
{
    return std::string(*parser[CLI::FILTER].begin());
}

const std::string Parameters::input_file() const
{
    std::string ifile;
    if(parser.is_default(CLI::IFILE))
    {
        std::stringstream buffer;
        buffer << parser[CLI::INTERFACE].begin()->to_cstr() << '-' << parser[CLI::FILTER].begin()->to_cstr() << ".pcap";
        ifile = buffer.str();
    }
    else
    {
        ifile = *parser[CLI::IFILE].begin();
    }
    // TODO: add file validation
    return ifile;
}

const std::string Parameters::output_file() const
{
    std::string ofile;
    if(parser.is_default(CLI::OFILE))
    {
        std::stringstream buffer;
        buffer << parser[CLI::INTERFACE].begin()->to_cstr() << '-' << parser[CLI::FILTER].begin()->to_cstr() << ".pcap";
        ofile = buffer.str();
    }
    else
    {
        ofile = *parser[CLI::OFILE].begin();
    }
    // TODO: add file validation
    return ofile;
}

const std::string Parameters::dumping_cmd() const
{
    return parser[CLI::COMMAND].begin()->to_cstr();
}

unsigned int Parameters::dumping_size() const
{
    unsigned int dsize = parser[CLI::DSIZE].begin()->to_int();
    if(dsize != 0 && output_file() == "-") // '-' is alias for stdout in libpcap dumps
    {
        throw cmdline::CLIError(std::string("Output file \"-\" means stdout, the dump-size must be 0"));
    }

    return dsize * 1024 * 1024; // MBytes
}

unsigned int Parameters::buffer_size() const
{
    const int size = parser[CLI::BSIZE].begin()->to_int();
    if(size < 1)
    {
        throw cmdline::CLIError(std::string("Invalid value of kernel buffer size: ") + parser[CLI::BSIZE].begin()->to_cstr());
    }

    return size * 1024 * 1024; // MBytes
}

unsigned short Parameters::rpcmsg_limit() const
{
    return rpc_message_limit;
}

unsigned short Parameters::queue_capacity() const
{
    const int capacity = parser[CLI::QSIZE].begin()->to_int();
    if(capacity < 1 || capacity > 65535)
    {
        throw cmdline::CLIError(std::string("Invalid value of queue capacity: ") + parser[CLI::QSIZE].begin()->to_cstr());
    }

    return capacity;
}

const std::vector<AParams> Parameters::analyzers() const
{
    std::vector<AParams> analyzers;

    Parser::ParamValsCIter it = parser[CLI::ANALYZERS].begin();
    Parser::ParamValsCIter end = parser[CLI::ANALYZERS].end();
    for(;it != end; ++it)
    {
        if(*it->to_cstr() == '\0')
            continue;
        std::string arg(it->to_cstr());
        size_t ind = arg.find('#');
        if(ind == std::string::npos)
        {
            analyzers.push_back(AParams(arg));
        }
        else
        {
            std::string path(arg, 0, ind);
            std::string args(arg, ind + 1);
            analyzers.push_back(AParams(path, args));
        }
    }
    return analyzers;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
