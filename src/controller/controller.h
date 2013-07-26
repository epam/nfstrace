//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONTROLLER_H
#define CONTROLLER_H
//------------------------------------------------------------------------------
#include "../analyzer/analysis_manager.h"
#include "../auxiliary/logger.h"
#include "../filter/filtration_manager.h"
#include "parameters.h"
#include "running_status.h"
#include "synchronous_signal_handling.h"
//------------------------------------------------------------------------------
using NST::analyzer::AnalysisManager;
using NST::auxiliary::Logger;
using NST::filter::FiltrationManager;
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
    // global used logger
    Logger logger; 

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
