//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control of the aplication
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONTROLLER_H
#define CONTROLLER_H
//------------------------------------------------------------------------------
#include "cmdline_args.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class Controller
{
public:
    Controller();
    ~Controller();

    int run(int argc, char** argv);

private:
    cmdline::Params params;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CONTROLLER_H
//------------------------------------------------------------------------------
