//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONTROLLER_H
#define CONTROLLER_H
//------------------------------------------------------------------------------
#include <memory>

#include "analysis/analysis_manager.h"
#include "filtration/filtration_manager.h"
#include "controller/parameters.h"
#include "controller/running_status.h"
#include "controller/signal_handler.h"
#include "utils/logger.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class Controller
{
    using AnalysisManager   = NST::analysis::AnalysisManager;
    using FiltrationManager = NST::filtration::FiltrationManager;

public:
    Controller(const Parameters& parameters);
    Controller(const Controller&)            = delete;
    Controller& operator=(const Controller&) = delete;
    ~Controller();

    int run();

private:

    // initializer of global logger
    utils::logger::Global glogger;

    // container for generated exceptions
    RunningStatus status;

    // signal handler
    SignalHandler signals;

    // controller contains instances of modules
    std::unique_ptr<AnalysisManager>   analysis;
    std::unique_ptr<FiltrationManager> filtration;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif//CONTROLLER_H
//------------------------------------------------------------------------------
