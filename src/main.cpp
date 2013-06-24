//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Entry point of program.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <exception>

#include "controller/controller.h"
//------------------------------------------------------------------------------
using namespace NST::controller;
//------------------------------------------------------------------------------
int main(int argc, char **argv) try
{
    Controller controller;

    if(!controller.cmdline_args(argc, argv))
    {
        return 0; // -h was passed
    }

    return controller.run();
}
catch(const std::exception& e)
{
    std::cerr << argv[0] << ": " << e.what() << std::endl;
    exit(-1);
}
catch(...)
{
    std::cerr << "Unknown error" << std::endl;
    exit(-1);
}
//------------------------------------------------------------------------------

