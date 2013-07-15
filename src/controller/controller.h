//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONTROLLER_H
#define CONTROLLER_H
//------------------------------------------------------------------------------
#include "../filter/filtration_manager.h"
#include "../analyzer/analysis_manager.h"
#include "parameters.h"
#include "running_status.h"
#include "synchronous_signal_handling.h"
//------------------------------------------------------------------------------
using NST::filter::FiltrationManager;
using NST::analyzer::AnalysisManager;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class Controller
{
public:

    Controller(const Parameters& parameters);
    ~Controller();

    int run();

private:
    // container for generated exceptions
    RunningStatus status;

    // signal handler. Working in its own thread
    SynchronousSignalHandling sig_handler;

    // controller contains instances of modules
    FiltrationManager filtration;
    AnalysisManager   analysis;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CONTROLLER_H
//------------------------------------------------------------------------------
