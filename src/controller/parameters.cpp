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
NST::controller::cmdline::CmdlineParser<CLI> parser;
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
    unsigned short snaplen = parser[CLI::SNAPLEN].to_int();
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

const Parameters::AString Parameters::analyzers() const
{
    AString analyzers;
    std::istringstream raw_analyzers(parser[CLI::ANALYZERS]);
    while(raw_analyzers)
    {
        std::string analyzer;
        if(!std::getline(raw_analyzers, analyzer, ',')) break;
        analyzers.push_back(analyzer);
    }
    validate_analyzers(analyzers);
    return analyzers;
}

void Parameters::validate_analyzers(const AString& analyzers)
{                 
    static std::string ob(CLI::ob_analyzer);
    static std::string ofws(CLI::ofws_analyzer);
    static std::string ofdws(CLI::ofdws_analyzer);

    ConstIterator i = analyzers.begin();
    ConstIterator end = analyzers.end();
    for(; i != end; ++i)
    {
        if(*i == ob) continue;
        if(*i == ofws) continue;
        if(*i == ofdws) continue;
        if(access(i->c_str(), F_OK))
            throw cmdline::CLIError(std::string("Unsupported analyzer: ") + *i);
    }
}

const std::string Parameters::input_file() const
{
    std::string ifile;
    if(parser.is_default(CLI::IFILE))
    {
        std::stringstream buffer;
        buffer << parser[CLI::INTERFACE].to_cstr() << '-' << parser[CLI::PORT].to_cstr() << '-' << parser[CLI::SNAPLEN].to_cstr() << ".pcap";
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
        buffer << parser[CLI::INTERFACE].to_cstr() << '-' << parser[CLI::PORT].to_cstr() << '-' << parser[CLI::SNAPLEN].to_cstr() << ".pcap";
        ofile = buffer.str();
    }
    else
    {
        ofile = parser[CLI::OFILE];
    }
    // TODO: add file validation
    return ofile;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
