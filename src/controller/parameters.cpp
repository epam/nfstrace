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
//------------------------------------------------------------------------------
typedef NST::controller::cmdline::Args CLI;
typedef NST::controller::cmdline::CmdlineParser<CLI> Parser;
static Parser parser;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

bool Parameters::cmdline_args(int argc, char** argv)
{
    parser.parse(argc, argv);
    if(parser[CLI::HELP].begin()->to_bool())
    {
        parser.print_usage(std::cout, argv[0]);
        return false;
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
    verbose = parser[CLI::VERBOSE].begin()->to_bool();

    return true;
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
    else if(mode == CLI::filtration_mode)
    {
        return Filtration;
    }
    else if(mode == CLI::analysis_mode)
    {
        return Analysis;
    }

    throw cmdline::CLIError(std::string("Unknown mode: ") + mode);
}

bool Parameters::is_verbose() const
{
    return verbose;
}

const std::string Parameters::interface() const
{
    return std::string(*parser[CLI::INTERFACE].begin());
}

unsigned short Parameters::snaplen() const
{
    const int snaplen = parser[CLI::SNAPLEN].begin()->to_int();
    if(snaplen != 65535)
    {
        throw cmdline::CLIError("Statefull filtration RPC messages over TCP requires snaplen = 65535");
    }
    return snaplen;
}

const std::string Parameters::filter() const
{
    return std::string("tcp port ") + std::string(*parser[CLI::PORT].begin());
}

const std::string Parameters::input_file() const
{
    std::string ifile;
    if(parser.is_default(CLI::IFILE))
    {
        std::stringstream buffer;
        buffer << parser[CLI::INTERFACE].begin()->to_cstr() << '-' << parser[CLI::PORT].begin()->to_cstr() << ".pcap";
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
        buffer << parser[CLI::INTERFACE].begin()->to_cstr() << '-' << parser[CLI::PORT].begin()->to_cstr() << ".pcap";
        ofile = buffer.str();
    }
    else
    {
        ofile = *parser[CLI::OFILE].begin();
    }
    // TODO: add file validation
    return ofile;
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

    static std::string ob(CLI::ob_analyzer);
    static std::string ofws(CLI::ofws_analyzer);
    static std::string ofdws(CLI::ofdws_analyzer);

    Parser::ParamValsCIter it = parser[CLI::ANALYZERS].begin();
    Parser::ParamValsCIter end = parser[CLI::ANALYZERS].end();
    for(;it != end; ++it)
    {
        std::string arg(it->to_cstr());
        size_t ind = arg.find('#');
        if(ind == std::string::npos)
        {
            if(!((arg == ob) || (arg == ofws) || (arg == ofdws)))
                throw cmdline::CLIError(std::string("Request to the unsupported internal analyzer: ") + arg);
            analyzers.push_back(AParams(arg));
        }
        else
        {
            std::string path(arg, 0, ind);
            std::string args(arg, ind + 1);
            if(access(path.c_str(), F_OK))
                throw cmdline::CLIError(std::string("Can't access to plugable module: ") + path);
            analyzers.push_back(AParams(path, args));
        }
    }
    return analyzers;
}

unsigned int Parameters::block_size() const
{
    const int bl_s = parser[CLI::BLSIZE].begin()->to_int();
    if(bl_s < 1)
        throw cmdline::CLIError(std::string("Invalid value of block size: ") + parser[CLI::BLSIZE].begin()->to_cstr());
    return bl_s * 1024;
}

unsigned int Parameters::bucket_size() const
{
    const int b_s = parser[CLI::BUSIZE].begin()->to_int();
    if(b_s < 1)
        throw cmdline::CLIError(std::string("Invalid value of bucket size: ") + parser[CLI::BUSIZE].begin()->to_cstr());
    return b_s;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
