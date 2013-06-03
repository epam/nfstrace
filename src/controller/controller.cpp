//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control of the aplication
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

Controller::Controller()
{
}

Controller::~Controller()
{
}

int Controller::run(int argc, char** argv)
{
    try
    {
        params.parse(argc, argv);
        if(params[cmdline::Args::HELP].to_bool())
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
    return 0;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
