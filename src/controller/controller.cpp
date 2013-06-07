//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <csignal>
#include <iostream>

#include "unistd.h"

#include "cmdline_args.h"
#include "controller.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

typedef cmdline::Args CLI;  // short alias for structure of cli-arguments

static Controller* g_controller = NULL;

Controller::Controller() : running(false)
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

bool Controller::set_signal_handlers()
{
    if(g_controller)
    {
        return false;
    }

    g_controller = this;

    if(signal(SIGINT,  Controller::signal_handler) == SIG_ERR
    || signal(SIGTERM, Controller::signal_handler) == SIG_ERR
    || signal(SIGPIPE, Controller::signal_handler) == SIG_ERR)
    {
        return false;
    }
    return true;
}

void Controller::signal_handler(int sig)
{
    // here we correctly signal_handler all nested objects and exit
    g_controller->stop();
    //std::cout << "signal_handler" << std::endl;
}

void Controller::stop()
{
    filtration.stop();
    running = false;
}

int Controller::run(int argc, char** argv)
{
    running = true;
    int parse_res = parse_cmdline_args(argc, argv);
    if(parse_res <= 0)
    {
        return parse_res;
    }

    if(!Controller::set_signal_handlers())
    {
        return -1;
    }
    
    
    if(params[CLI::DUMP].to_bool())   // online dump mode
    {
        init_online_dump();
    }

    // start modules to processing
    filtration.start();

    while(running)
    {
        sleep(1);
    }

    return 0;
}

void Controller::init_online_dump()
{
    const std::string iface = params[CLI::INTERFACE];
    const std::string port  = params[CLI::PORT];
    const std::string slen  = params[CLI::SNAPLEN];
    unsigned short snaplen  = params[CLI::SNAPLEN].to_int();
    const std::string filter= "tcp port " + port;
    
    const std::string ofile = params.is_default(CLI::OFILE) ?
                                iface+"-"+port+"-"+slen+".pcap" :
                                params[CLI::OFILE];

    filtration.dump_to_file(iface, filter, snaplen, 100, ofile);
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
