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

#include "../filter/filtration_manager.h"
#include "../analyzer/analyse_manager.h"
#include "synchronous_signal_handling.h"
#include "running_status.h"
//------------------------------------------------------------------------------
using NST::filter::FiltrationManager;
using NST::analyzer::AnalyseManager;
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
    int parse_cmdline_args(int argc, char** argv);

    void init_runing();

    // this object stores command-line parameters of the application
    cmdline::Params params;

    // Container for generated exceptions
    RunningStatus status;

    // Signal handler. Working in its own thread.
    SynchronousSignalHandling sig_handler;

    // Controller contains instances of modules
    FiltrationManager filtration;
    AnalyseManager analyse;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CONTROLLER_H
//------------------------------------------------------------------------------
