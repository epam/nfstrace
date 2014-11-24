//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class provides validation and access to application parameters
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
#include <iostream>

#include <unistd.h>

#include "analysis/plugin.h"
#include "controller/cmdline_args.h"
#include "controller/cmdline_parser.h"
#include "controller/parameters.h"
#include "controller/build_info.h"
#include "filtration/pcap/network_interfaces.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

namespace // implementation
{

static const class ParametersImpl* impl = nullptr;

using CLI = NST::controller::cmdline::Args;

class ParametersImpl : public cmdline::CmdlineParser<CLI>
{
    friend class NST::controller::Parameters;

    ParametersImpl(int argc, char** argv)
    : rpc_message_limit{0}
    {
        parse(argc, argv);
        if(get(CLI::HELP).to_bool())
        {
            std::cout << PROGRAM_BUILD_INFO << std::endl;
            print_usage(std::cout, argv[0]);

            for(const auto& a : analysis_modules)
            {
                const std::string& path {a.path};
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

        if(get(CLI::LIST).to_bool())
        {
            NST::filtration::pcap::NetworkInterfaces interfaces;
            if(interfaces.begin() != interfaces.end())
            {
                for(auto i : interfaces)
                {
                    std::cout << i << '\n';
                    for(auto a : i) std::cout << '\t' << a << '\n';
                }
                std::cout << "[default]: " <<  interfaces.default_device() << '\n';
            }
            else
            {
                std::cerr << "Note: Reading list of network interfaces may "
                             "require that you have special privileges." << std::endl;
            }
        }

        // cashed values
        const std::string program_path(argv[0]);
        size_t found {program_path.find_last_of("/\\")};
        program = program_path.substr(found+1);

        const int limit {get(CLI::MSIZE).to_int()};
        if(limit < 1 || limit > 4000)
        {
            throw cmdline::CLIError{std::string{"Invalid limit of RPC messages: "} + get(CLI::MSIZE).to_cstr()};
        }

        rpc_message_limit = limit;
    }
    virtual ~ParametersImpl(){}
    ParametersImpl(const ParametersImpl&)            = delete;
    ParametersImpl& operator=(const ParametersImpl&) = delete;

protected:
    void set_multiple_value(int index, char *const v) override
    {
        if(index == CLI::ANALYZERS) // may have multiple values
        {
            const std::string arg{v};
            size_t ind {arg.find('#')};
            if(ind == std::string::npos)
            {
                analysis_modules.emplace_back(path_to_pam(arg));
            }
            else
            {
                const std::string path{arg, 0, ind};
                const std::string args{arg, ind + 1};
                analysis_modules.emplace_back(path_to_pam(path), args);
            }
        }
    }

private:
    std::string default_iofile() const
    {
        // create string: PROGRAMNAME-BPF-FILTER.pcap
        std::string str { impl->program };
        str.push_back('-');
        str.append(get(CLI::FILTER).to_cstr());
        str.append(".pcap");
        std::replace(str.begin(), str.end(), ' ', '-');
        return str;
    }

    std::string path_to_pam(const std::string& path) const
    {
        std::string result_path;

        if(access(path.c_str(), F_OK) != -1)
        {
            result_path = path;
        }
        else
        {
            result_path = std::string{MODULES_DIRECTORY_PATH} + path;
        }
        return result_path;
    }

    // cashed values
    unsigned short rpc_message_limit;
    std::string program;  // name of program in command line
    std::vector<AParams> analysis_modules;
};

} // unnamed namespace

Parameters::Parameters(int argc, char** argv)
{
    // init global instance only once
    if(impl) throw std::runtime_error{"initialized twice"};
    impl = new ParametersImpl(argc, argv);
}

Parameters::~Parameters()
{
    delete impl;
    impl = nullptr;
}

bool Parameters::show_help() const
{
    return impl->get(CLI::HELP).to_bool();
}

bool Parameters::show_list() const
{
    return impl->get(CLI::LIST).to_bool();
}

const std::string& Parameters::program_name() const
{
    return impl->program;
}

RunningMode Parameters::running_mode() const
{
    const auto& mode = impl->get(CLI::MODE);
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
    else if(mode.is(CLI::draining_mode))
    {
        return RunningMode::Draining;
    }
    throw cmdline::CLIError{std::string{"Unknown mode: "} + mode.to_cstr()};
}

std::string Parameters::input_file() const
{
    // TODO: add file validation
    return impl->is_default(CLI::IFILE) ? impl->default_iofile() : impl->get(CLI::IFILE);
}

const std::string Parameters::dropuser() const
{
    return impl->get(CLI::DROPROOT);
}

unsigned short Parameters::queue_capacity() const
{
    const int capacity = impl->get(CLI::QSIZE).to_int();
    if(capacity < 1 || capacity > 65535)
    {
        throw cmdline::CLIError(std::string{"Invalid value of queue capacity: "}
                                 + impl->get(CLI::QSIZE).to_cstr());
    }

    return capacity;
}

bool Parameters::trace() const
{
    // enable tracing if no analysis module was passed
    return impl->get(CLI::TRACE).to_bool() || impl->analysis_modules.empty();
}

int Parameters::verbose_level() const
{
    return impl->get(CLI::VERBOSE).to_int();
}

const Parameters::CaptureParams Parameters::capture_params() const
{
    Parameters::CaptureParams params;
    params.interface    = impl->get(CLI::INTERFACE);
    params.filter       = impl->get(CLI::FILTER);
    params.snaplen      = impl->get(CLI::SNAPLEN).to_int();
    params.timeout_ms   = impl->get(CLI::TIMEOUT).to_int();
    params.buffer_size  = impl->get(CLI::BSIZE).to_int() * 1024 * 1024; // MBytes
    params.promisc      = impl->get(CLI::PROMISC).to_bool();

    // check interface
    if(impl->is_default(CLI::INTERFACE))
    {
        params.interface = NST::filtration::pcap::NetworkInterfaces::default_device();
    }

    // check capture buffer size
    if(params.buffer_size < 1024 * 1024) // less than 1 MBytes
    {
        throw cmdline::CLIError{std::string{"Invalid value of kernel buffer size: "}
                                 + impl->get(CLI::BSIZE).to_cstr()};
    }

    // check max length of raw captured UDP packet
    if(params.snaplen < 1 || params.snaplen > 65535)
    {
        throw cmdline::CLIError{std::string{"Invalid value of max length of raw captured UDP packet: "}
                                 + impl->get(CLI::SNAPLEN).to_cstr()};
    }

    // check the read timeout that will be used on a capture
    if(params.timeout_ms < 1)
    {
        throw cmdline::CLIError{std::string{"Invalid value of read timeout that will be used on a capture: "}
                                 + impl->get(CLI::TIMEOUT).to_cstr()};
    }

    // check and set capture direction
    const auto& direction = impl->get(CLI::DIRECTION);
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
        throw cmdline::CLIError{std::string{"Unknown capturing direction: "}
                                 + direction.to_cstr()};
    }

    return params;
}

const Parameters::DumpingParams Parameters::dumping_params() const
{
    std::string ofile = impl->is_default(CLI::OFILE) ? impl->default_iofile() : impl->get(CLI::OFILE);
    // TODO: add file validation

    const int dsize = impl->get(CLI::DSIZE).to_int();
    if(dsize != 0 && ofile == "-") // '-' is alias for stdout in libpcap dumps
    {
        throw cmdline::CLIError{std::string{"Output file \"-\" means stdout, the dump-size must be 0"}};
    }

    Parameters::DumpingParams params;
    params.output_file = ofile;
    params.command     = impl->get(CLI::COMMAND);
    params.size_limit  = dsize * 1024 * 1024; // MBytes
    return params;
}

const std::vector<AParams>& Parameters::analysis_modules() const
{
    return impl->analysis_modules;
}

unsigned short Parameters::rpcmsg_limit()
{
    return impl->rpc_message_limit;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
