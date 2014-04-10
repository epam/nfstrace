//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class provides validation and access to application parameters
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <algorithm>
#include <iostream>

#include <unistd.h>

#include "analysis/plugin.h"
#include "controller/parameters.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

using CLI = NST::controller::cmdline::Args;

static const char program_build_information[]=
// the NST_BUILD_VERSION, NST_BUILD_PLATFORM and NST_BUILD_COMPILER
// should be defined by compilation options
#ifdef NST_BUILD_VERSION
    #define STR(x) DO_STR(x)
    #define DO_STR(x) #x
        STR(NST_BUILD_VERSION) "\n"
       "built on " STR(NST_BUILD_PLATFORM) "\n"
       "by C++ compiler " STR(NST_BUILD_COMPILER);
    #undef DO_STR
    #undef STR
#else
    "";
#endif

Parameters* Parameters::global = nullptr;

Parameters::Parameters(int argc, char** argv) : rpc_message_limit(0)
{
    if(global != nullptr) return; // init global instance only once

    parse(argc, argv);
    if(get(CLI::HELP).to_bool())
    {
        std::cout << program_build_information << std::endl;
        print_usage(std::cout, argv[0]);

        for(const auto& a : analysis_modules())
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
    const auto& mode = get(CLI::MODE);
    if(mode.is(CLI::profiling_mode))
    {
        return RunningMode::Profiling;
    }
    else if(mode.is(CLI::dumping_mode))
    {
        return RunningMode::Dumping;
    }
    else if(mode.is(CLI::analysis_mode))
    {
        return RunningMode::Analysis;
    }

    throw cmdline::CLIError{std::string("Unknown mode: ") + mode.to_cstr()};
}

std::string Parameters::input_file() const
{
    // TODO: add file validation
    return is_default(CLI::IFILE) ? default_iofile() : get(CLI::IFILE);
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

bool Parameters::trace() const
{
    // enable tracing if no analysis module was passed
    return get(CLI::TRACE).to_bool() || analysis_modules().empty();
}

int Parameters::verbose_level() const
{
    return get(CLI::VERBOSE).to_int();
}

const Parameters::CaptureParams Parameters::capture_params() const
{
    Parameters::CaptureParams params;
    params.interface    = get(CLI::INTERFACE);
    params.filter       = get(CLI::FILTER);
    params.snaplen      = get(CLI::SNAPLEN).to_int();
    params.timeout_ms   = get(CLI::TIMEOUT).to_int();
    params.buffer_size  = get(CLI::BSIZE).to_int() * 1024 * 1024; // MBytes
    params.promisc      = get(CLI::PROMISC).to_bool();

    // check interface
    if(params.interface.empty())
    {
        const char* mode = get(CLI::MODE).to_cstr();
        throw cmdline::CLIError{std::string{"Interface is required for "} + mode + " mode"};
    }

    // check capture buffer size
    if(params.buffer_size < 1024 * 1024) // less than 1 MBytes
    {
        throw cmdline::CLIError{std::string{"Invalid value of kernel buffer size: "} + get(CLI::BSIZE).to_cstr()};
    }

    // check and set capture direction
    const auto& direction = get(CLI::DIRECTION);
    if(direction.is("in"))
    {
        params.direction = decltype(params.direction)::IN;
    }
    else if(direction.is("out"))
    {
        params.direction = decltype(params.direction)::OUT;
    }
    else if(direction.is("inout"))
    {
        params.direction = decltype(params.direction)::INOUT;
    }
    else
    {
        throw cmdline::CLIError{std::string{"Unknown capturing direction: "} + direction.to_cstr()};
    }

    return params;
}

const Parameters::DumpingParams Parameters::dumping_params() const
{
    std::string ofile = is_default(CLI::OFILE) ? default_iofile() : get(CLI::OFILE);
    // TODO: add file validation

    const int dsize = get(CLI::DSIZE).to_int();
    if(dsize != 0 && ofile == "-") // '-' is alias for stdout in libpcap dumps
    {
        throw cmdline::CLIError(std::string("Output file \"-\" means stdout, the dump-size must be 0"));
    }

    Parameters::DumpingParams params;
    params.output_file = ofile;
    params.command     = get(CLI::COMMAND);
    params.size_limit  = dsize * 1024 * 1024; // MBytes
    return params;
}

const std::vector<AParams>& Parameters::analysis_modules() const
{
    return analysiss_params;
}

void Parameters::set_multiple_value(int index, char *const v)
{
    if(index == CLI::ANALYZERS) // may have multiple values
    {
        const std::string arg(v);
        size_t ind = arg.find('#');
        if(ind == std::string::npos)
        {
            analysiss_params.emplace_back(arg);
        }
        else
        {
            const std::string path(arg, 0, ind);
            const std::string args(arg, ind + 1);
            analysiss_params.emplace_back(path, args);
        }
    }
}

std::string Parameters::default_iofile() const
{
    // create string: INTERFACE-BPF-FILTER.pcap
    std::string str{ get(CLI::INTERFACE).to_cstr() };
    str.push_back('-');
    str.append(get(CLI::FILTER).to_cstr());
    str.append(".pcap");
    std::replace(str.begin(), str.end(), ' ', '-');
    return str;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
