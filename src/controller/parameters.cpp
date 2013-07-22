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
static NST::controller::cmdline::CmdlineParser<CLI> parser;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

bool Parameters::cmdline_args(int argc, char** argv)
{
    parser.parse(argc, argv);
    if(parser[CLI::HELP].to_bool())
    {
        parser.print_usage(std::cout, argv[0]);
        return false;
    }
    parser.validate();

    // cashed values
    const int limit = parser[CLI::MSIZE].to_int();
    if(limit < 1 || limit > 4000)
    {
        throw cmdline::CLIError(std::string("Invalid limit of RPC messages: ") + parser[CLI::MSIZE].to_cstr());
    }

    rpc_message_limit = limit;
    verbose = parser[CLI::VERBOSE].to_bool();

    return true;
}

const RunningMode Parameters::running_mode() const
{
    const std::string mode = parser[CLI::MODE];
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

const bool Parameters::is_verbose() const
{
    return verbose;
}

const std::string Parameters::interface() const
{
    return std::string(parser[CLI::INTERFACE]);
}

const unsigned short Parameters::snaplen() const
{
    const int snaplen = parser[CLI::SNAPLEN].to_int();
    if(snaplen != 65535)
    {
        throw cmdline::CLIError("Statefull filtration RPC messages over TCP requires snaplen = 65535");
    }
    return snaplen;
}

const std::string Parameters::filter() const
{
    return std::string("tcp port ") + std::string(parser[CLI::PORT]);
}

const std::string Parameters::input_file() const
{
    std::string ifile;
    if(parser.is_default(CLI::IFILE))
    {
        std::stringstream buffer;
        buffer << parser[CLI::INTERFACE].to_cstr() << '-' << parser[CLI::PORT].to_cstr() << ".pcap";
        ifile = buffer.str();
    }
    else
    {
        ifile = parser[CLI::IFILE];
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
        buffer << parser[CLI::INTERFACE].to_cstr() << '-' << parser[CLI::PORT].to_cstr() << ".pcap";
        ofile = buffer.str();
    }
    else
    {
        ofile = parser[CLI::OFILE];
    }
    // TODO: add file validation
    return ofile;
}

const unsigned int Parameters::buffer_size() const
{
    const int size = parser[CLI::BSIZE].to_int();
    if(size < 1)
    {
        throw cmdline::CLIError(std::string("Invalid value of kernel buffer size: ") + parser[CLI::BSIZE].to_cstr());
    }

    return size * 1024 * 1024; // MBytes
}

const unsigned short Parameters::rpcmsg_limit() const
{
    return rpc_message_limit;
}

const unsigned short Parameters::queue_capacity() const
{
    const int capacity = parser[CLI::QSIZE].to_int();
    if(capacity < 1 || capacity > 65535)
    {
        throw cmdline::CLIError(std::string("Invalid value of queue capacity: ") + parser[CLI::QSIZE].to_cstr());
    }

    return capacity;
}

const std::vector<std::string> Parameters::analyzers() const
{
    static std::string ob(CLI::ob_analyzer);
    static std::string ofws(CLI::ofws_analyzer);
    static std::string ofdws(CLI::ofdws_analyzer);
    
    std::vector<std::string> analyzers;
    std::istringstream raw_analyzers(parser[CLI::ANALYZERS]);
    while(raw_analyzers)
    {
        std::string analyzer;
        if(!std::getline(raw_analyzers, analyzer, ',')) break;
        analyzers.push_back(analyzer);
    }

    for(unsigned int i = 0; i < analyzers.size(); ++i)
    {
        std::string& analyzer = analyzers[i];
        if((analyzer == ob) || (analyzer == ofws) || (analyzer == ofdws))
            continue;
        if(access(analyzer.c_str(), F_OK))
            throw cmdline::CLIError(std::string("Can't access to plugable module: ") + analyzer);
    }
    return analyzers;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
