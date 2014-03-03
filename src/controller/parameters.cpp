//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class provides validation and access to application parameters
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <sstream>

#include <unistd.h>

#include "controller/parameters.h"
#include "analysis/plugin.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

using CLI = NST::controller::cmdline::Args;

Parameters* Parameters::global = nullptr;

Parameters::Parameters(int argc, char** argv) : rpc_message_limit(0)
{
    if(global != nullptr) return; // init global instance only once

    parse(argc, argv);
    if(get(CLI::HELP).to_bool())
    {
        print_usage(std::cout, argv[0]);

        for(auto& a : analysiss())
        {
            const std::string& path = a.path;
            try
            {
                std::cout << "Usage of " << path << ":\n";
                std::cout << NST::analysis::Plugin::usage_of(path) << std::endl;
            }
            catch(std::runtime_error& e)
            {
                std::cout << e.what() << std::endl;
            }
        }
        return;
    }
    validate();

    // cashed values
    const std::string program_path(argv[0]);
    size_t found = program_path.find_last_of("/\\");
    program = program_path.substr(found+1);

    const int limit = get(CLI::MSIZE).to_int();
    if(limit < 1 || limit > 4000)
    {
        throw cmdline::CLIError(std::string("Invalid limit of RPC messages: ") + get(CLI::MSIZE).to_cstr());
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
    const std::string mode = get(CLI::MODE);
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
    return get(CLI::VERBOSE).to_bool();
}

std::string Parameters::interface() const
{
    const std::string itf = get(CLI::INTERFACE);

    if(itf.empty())
    {
        const char* mode = get(CLI::MODE).to_cstr();
        throw cmdline::CLIError(std::string("Interface is required for ") + mode + " mode");
    }

    return itf;
}

unsigned short Parameters::snaplen() const
{
    return get(CLI::SNAPLEN).to_int();
}

int Parameters::timeout() const
{
    return get(CLI::TIMEOUT).to_int();
}

std::string Parameters::filtration() const
{
    return get(CLI::FILTER);
}

std::string Parameters::input_file() const
{
    std::string ifile;
    if(is_default(CLI::IFILE))
    {
        std::stringstream buffer;
        buffer << get(CLI::INTERFACE).to_cstr() << '-' << get(CLI::FILTER).to_cstr() << ".pcap";
        ifile = buffer.str();
    }
    else
    {
        ifile = get(CLI::IFILE);
    }
    // TODO: add file validation
    return ifile;
}

std::string Parameters::output_file() const
{
    std::string ofile;
    if(is_default(CLI::OFILE))
    {
        std::stringstream buffer;
        buffer << get(CLI::INTERFACE).to_cstr() << '-' << get(CLI::FILTER).to_cstr() << ".pcap";
        ofile = buffer.str();
    }
    else
    {
        ofile = get(CLI::OFILE);
    }
    // TODO: add file validation
    return ofile;
}

std::string Parameters::dumping_cmd() const
{
    return get(CLI::COMMAND);
}

unsigned int Parameters::dumping_size() const
{
    const int dsize = get(CLI::DSIZE).to_int();
    if(dsize != 0 && output_file() == "-") // '-' is alias for stdout in libpcap dumps
    {
        throw cmdline::CLIError(std::string("Output file \"-\" means stdout, the dump-size must be 0"));
    }

    return dsize * 1024 * 1024; // MBytes
}

int Parameters::buffer_size() const
{
    const int size = get(CLI::BSIZE).to_int();
    if(size < 1)
    {
        throw cmdline::CLIError(std::string("Invalid value of kernel buffer size: ") + get(CLI::BSIZE).to_cstr());
    }

    return size * 1024 * 1024; // MBytes
}

unsigned short Parameters::rpcmsg_limit() const
{
    return rpc_message_limit;
}

unsigned short Parameters::queue_capacity() const
{
    const int capacity = get(CLI::QSIZE).to_int();
    if(capacity < 1 || capacity > 65535)
    {
        throw cmdline::CLIError(std::string("Invalid value of queue capacity: ") + get(CLI::QSIZE).to_cstr());
    }

    return capacity;
}

const std::vector<AParams>& Parameters::analysiss() const
{
    return analysiss_params;
}

void Parameters::set_multiple_value(int index, char *const v)
{
    if(index == CLI::ANALYZERS) // may have multiple values
    {
        std::string arg(v);
        size_t ind = arg.find('#');
        if(ind == std::string::npos)
        {
            analysiss_params.push_back(AParams(arg));
        }
        else
        {
            std::string path(arg, 0, ind);
            std::string args(arg, ind + 1);
            analysiss_params.push_back(AParams(path, args));
        }
    }
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
