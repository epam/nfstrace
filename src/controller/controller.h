//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
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
    bool set_signal_handlers();
    static void signal_handler(int sig);
    int parse_cmdline_args(int argc, char** argv);
    void stop();
    bool running;
    cmdline::Params params;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CONTROLLER_H
//------------------------------------------------------------------------------
