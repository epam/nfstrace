//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "cmdline_args.h"
#include "controller.h"
#include "../auxiliary/filtered_data.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

typedef cmdline::Args CLI;  // short alias for structure of cli-arguments

Controller::Controller() : sig_handler(status), filtration(status), analysis(status)
{
}

Controller::~Controller()
{
}

bool Controller::cmdline_args(int argc, char** argv)
{
    params.parse(argc, argv);
    if(params[CLI::HELP].to_bool())
    {
        params.print_usage(std::cout, argv[0]);
        return false;
    }
    params.validate();

    if(params[CLI::SNAPLEN].to_int() != 65535)
    {
        throw cmdline::CLIError("Statefull filtration RPC messages over TCP requires snaplen = 65535");
    }

    return true;
}

int Controller::run()
{
    init_runing();

    // Start handling user signals
    sig_handler.create();

    // Start modules to processing
    filtration.start();
    analysis.start();

    // Waiting some exception or user-signal for handling
    // TODO: add code for recovery processing
    try
    {
        status.wait_and_rethrow_exception();
    }
    catch(...)
    {
        filtration.stop();
        analysis.stop();
        status.print(std::cerr);
        sig_handler.stop();
        throw;
    }

    return 0;
}

void Controller::init_runing()
{
    const bool verbose      = params[CLI::VERBOSE].to_bool();
    const std::string mode  = params[CLI::MODE];
    const std::string iface = params[CLI::INTERFACE];
    const std::string port  = params[CLI::PORT];
    const std::string slen  = params[CLI::SNAPLEN];
    unsigned short snaplen  = params[CLI::SNAPLEN].to_int();
    const std::string filter= "tcp port " + port;
    const unsigned int ms   = 100;

    if(mode == CLI::profiling_mode)
    {
        NST::auxiliary::FilteredDataQueue& queue = analysis.init(verbose);

        filtration.capture_to_queue(queue, iface, filter, snaplen, ms);
    }
    else if(mode == CLI::filtration_mode)
    {
        const std::string ofile = params.is_default(CLI::OFILE) ?
                                iface+"-"+port+"-"+slen+".pcap" :
                                params[CLI::OFILE];

        filtration.dump_to_file(ofile, iface, filter, snaplen, ms);
    }
    else if(mode == CLI::analysis_mode)
    {
        NST::auxiliary::FilteredDataQueue& queue = analysis.init(verbose);

        const std::string ifile = params.is_default(CLI::IFILE) ?
                                iface+"-"+port+"-"+slen+".pcap" :
                                params[CLI::IFILE];

        filtration.read_to_queue(queue, ifile);
    }
    else
    {
        throw cmdline::CLIError(std::string("unknown mode: ") + mode);
    }
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
