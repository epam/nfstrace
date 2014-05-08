//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Entry point of program.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <exception>

#include "controller/controller.h"
#include "controller/parameters.h"
//------------------------------------------------------------------------------
using namespace NST::controller;
//------------------------------------------------------------------------------
int main(int argc, char **argv) try
{
    Parameters params(argc, argv); // set and validate CLI options

    if(params.show_help() || params.show_list())
    {
        return 0; // -h or -L was passed
    }

    Controller controller(params);

    return controller.run();
}
catch(const std::exception& e)
{
    std::cerr << argv[0] << ": " << e.what() << std::endl;
    return -1;
}
catch(...)
{
    std::cerr << "Unknown error" << std::endl;
    return -1;
}
//------------------------------------------------------------------------------

