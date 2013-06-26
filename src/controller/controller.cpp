//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "cmdline_args.h"
#include "controller.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

typedef cmdline::Args CLI;  // short alias for structure of cli-arguments

Controller::Controller() : sig_handler(status), filtration(status), analyse(status)
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

    return true;
}

int Controller::run()
{
    init_runing();

    // Start handling user signals
    sig_handler.create();

    // Start modules to processing
    filtration.start();
    analyse.start();

    // Waiting some exception or user-signal for handling
    // TODO: add code for recovery processing
    try
    {
        status.wait_and_rethrow_exception();
    }
    catch(...)
    {
        filtration.stop();
        analyse.stop();
        status.print(std::cerr);
        sig_handler.stop();
        throw;
    }

    return 0;
}

void Controller::init_runing()
{
    const std::string mode  = params[CLI::MODE];
    const std::string iface = params[CLI::INTERFACE];
    const std::string port  = params[CLI::PORT];
    const std::string slen  = params[CLI::SNAPLEN];
    unsigned short snaplen  = params[CLI::SNAPLEN].to_int();
    const std::string filter= "tcp port " + port;
    const unsigned int ms   = 100;

    if(mode == "dump")   // online dump mode
    {
        const std::string ofile = params.is_default(CLI::OFILE) ?
                                iface+"-"+port+"-"+slen+".pcap" :
                                params[CLI::OFILE];

        filtration.dump_to_file(ofile, iface, filter, snaplen, ms);
    }
    else if(mode == "mon")   // online monitoring mode
    {
        NFSQueue& queue = analyse.init();
        filtration.capture_to_queue(queue, iface, filter, snaplen, ms);
        analyse.print_analyzer();
    }
    else if(mode == "stat")   // offline analysis mode
    {
        throw cmdline::CLIError(std::string("unimplemented mode: ") + mode);
    }
    else
    {
        throw cmdline::CLIError(std::string("unknown mode: ") + mode);
    }
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
