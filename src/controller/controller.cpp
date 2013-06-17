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

Controller::Controller() : sig_handler(excpts_holder), filtration(excpts_holder)
{
}

Controller::~Controller()
{
}

int Controller::parse_cmdline_args(int argc, char** argv)
{
    try
    {
        params.parse(argc, argv);
        if(params[CLI::HELP].to_bool())
        {
            params.print_usage(std::cout, argv[0]);
            return 0;
        }
        params.validate();
    }
    catch(const cmdline::CLIError& e)
    {
        std::cerr << argv[0] << ": " << e.what() << std::endl;
        return -1;
    }
    return 1;
}

int Controller::run(int argc, char** argv)
{
    int parse_res = parse_cmdline_args(argc, argv);
    if(parse_res <= 0)
    {
        return parse_res;
    }

    init_runing();

    // Start handling user signals
    sig_handler.create();
    
    // Start modules to processing
    filtration.start();

    // Waiting some exception or user-signal for handling
    std::auto_ptr<std::exception> e(excpts_holder.pop_wait());
    std::cerr << e->what() << std::endl;

    // Stop all modules here
    filtration.stop();
    excpts_holder.print(std::cerr);
    sig_handler.stop();

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
        filtration.capture_to_queue(/*queue*/ iface, filter, snaplen, ms);
    }
    else if(mode == "stat")   // offline analysis mode
    {
    }
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
